#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Performs an openscap oval evaluation and writes security errata
# as facter facts.
#
# Copyright (C) 2017 by The Linux Foundation and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)
import os
import sys
import yaml
import requests
import subprocess
import time
import logging

from argparse import ArgumentParser

from lxml import etree


ns = {
        'def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'res': 'http://oval.mitre.org/XMLSchema/oval-results-5',
        'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
     }

logger = logging.getLogger(__name__)


def main(vardir, factfile, defurl, deffixes=(), chsevs=(), rebootpkgs=()):
    tries = 1
    success = False
    local_defs = os.path.join(vardir, 'oval-definitions.xml')

    while tries < 4:
        logger.info('Downloading %s (try %s)' % (defurl, tries))
        try:
            r = requests.get(defurl, stream=True)
            with open(local_defs, 'w') as fh:
                for chunk in r.iter_content(chunk_size=8092):
                    if chunk:
                        fh.write(chunk)
            fh.close()
            success = True
            break
        except Exception as ex:
            logger.info('Error downloading: %s' % ex)
            logger.info('Sleeping for 1 minute')
            tries += 1
            time.sleep(60)

    if not success:
        logger.info('Was not able to download %s, giving up' % defurl)
        # We exit with code 0 and will let nagios file age monitoring to alert
        # when an oscap report hasn't run in a bit
        sys.exit(0)

    if len(deffixes):
        try:
            root = etree.parse(local_defs).getroot()
            for (ovalid, fix) in deffixes.items():
                matchelt = root.find('.//*[@id="%s"]' % ovalid)
                if matchelt is not None:
                    child = matchelt.getchildren()[0]
                    child.text = fix
                    logger.info('Fixed definition %s=%s' % (ovalid, fix))
                else:
                    logger.info('Did not find anything matching %s' % ovalid)
                    # This will probably give us false-negatives for results, so
                    # exit now and let nagios alert us.
                    sys.exit(0)

            fh = open(local_defs, 'w')
            fh.write(etree.tostring(root, pretty_print=True))
            fh.close()

        except Exception as ex:
            logger.info('Error mangling %s' % local_defs)
            logger.info('Exception: %s' % ex)
            sys.exit(0)

    # Next we run oscap oval eval
    resfile = os.path.join(vardir, 'oval-results.xml')
    repfile = os.path.join(vardir, 'oval-report.html')
    args = ['oscap', 'oval', 'eval', '--results', resfile, '--report', repfile, local_defs]
    logger.info('Running: %s' % ' '.join(args))

    (output, error) = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    error = error.strip()
    if error:
        logger.info('Error running oscap eval: %s' % error)
        # We exit with code 0 and will let nagios file age monitoring to alert
        # when an oscap report hasn't run in a bit
        sys.exit(0)

    logger.info('Parsing %s' % resfile)

    try:
        doc = etree.parse(resfile).getroot()

        res = doc.find('res:results', ns)
        defs = doc.find('def:oval_definitions', ns)

        oval = {'rhsa': {},
                'cve' : {},
                'severity': {},
                }

        for sddelt in res.findall('res:system/res:definitions/res:definition[@result="true"]', ns):
            defid = sddelt.get('definition_id')
            defelt = defs.find('def:definitions/def:definition[@id="%s"]' % defid, ns)
            metaelt = defelt.find('def:metadata', ns)
            title = metaelt.find('def:title', ns).text
            severity = metaelt.find('def:advisory/def:severity', ns).text.lower()

            for refelt in metaelt.findall('def:reference', ns):
                refid  = refelt.get('ref_id')
                refurl = refelt.get('ref_url')
                for chid, new_severity in chsevs.items():
                    if refid.find(chid) == 0:
                        logger.info('Changed severity on %s: %s => %s' % (refid, severity, new_severity))
                        severity = new_severity.lower()
                        break

                source = refelt.get('source').lower()
                if refid not in oval[source]:
                        oval[source][refid] = refurl

            if severity in ('ignore', 'none'):
                logger.info('Ignoring: %s' % title)

            else:
                if severity not in oval['severity']:
                    oval['severity'][severity] = {
                        'count': 0,
                        'titles': [],
                    }

                logger.info('Found: %s' % title)
                oval['severity'][severity]['count'] += 1
                oval['severity'][severity]['titles'].append(title)

    except Exception as ex:
        logger.info('Was not able to parse %s' % resfile)
        logger.info('Error returned: %s' % ex)
        # We exit with code 0 and will let nagios file age monitoring to alert
        # when an oscap report hasn't run in a bit
        sys.exit(0)

    facts = { 'openscap': {
                'oval': oval,
              }
            }

    if rebootpkgs:
        # Some magic taken from yum-utils needs-restarting
        # I miss you Seth.
        import yum
        sys.path.insert(0,'/usr/share/yum-cli')
        import utils
        my = yum.YumBase()
        my.preconf.init_plugins = False
        if hasattr(my, 'setCacheDir'):
            my.conf.cache = True

        boot_time = utils.get_boot_time()
        stale_pkgs = []

        for pkg in my.rpmdb.searchNames(rebootpkgs):
            if float(pkg.installtime) > float(boot_time):
                logger.info('Core package %s updated, system needs reboot.' % pkg)
                stale_pkgs.append(str(pkg))

        if len(stale_pkgs):
            facts['openscap']['oval']['needs_reboot'] = True
            facts['openscap']['oval']['reboot_pkgs'] = stale_pkgs

    try:
        logger.info('Writing %s' % factfile)
        fout = open(factfile, 'w')
        yaml.safe_dump(facts, fout, default_flow_style=False, explicit_start=True)
        fout.close()
        # set perms on that file to 0600 just in case it's not already
        os.chmod(factfile, 0o600)
    except Exception as ex:
        # The only critical error
        logger.critical('Was not able to write to %s' % factfile)
        sys.exit(1)

if __name__ == '__main__':
    parser = ArgumentParser(description='Convert oval results into puppet facts')
    parser.add_argument('--vardir', default='/var/lib/openscap',
        help='where to keep intermediate files (%(default)s)')
    parser.add_argument('--factfile', default='/etc/puppetlabs/facter/facts.d/openscap.yaml',
        help='where to write the resulting yaml (%(default)s)')
    parser.add_argument('--defurl', help='url with oval definitions')
    parser.add_argument('--logfile', default='/var/log/openscap-oval-facter.log',
        help='log things into this logfile (%(default)s)')
    parser.add_argument('--sleep', type=int, help='randomly sleep up to this many seconds')
    parser.add_argument('--quiet', action='store_true', help='only output critical errors')
    parser.add_argument('--tweaks', help='Yaml file with definition tweaks and overrides')
    parser.add_argument('--needsreboot', action='store_true',
        help='Hint if a system needs a reboot')

    args = parser.parse_args()

    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(args.logfile)
    formatter = logging.Formatter("[%(process)d] %(asctime)s - %(message)s")
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    loglevel = logging.INFO
    if args.quiet:
        loglevel = logging.CRITICAL

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(loglevel)
    logger.addHandler(ch)

    if args.sleep:
        import random
        logger.info('Sleeping up to %s seconds' % args.sleep)
        time.sleep(random.randint(0, args.sleep))

    deffixes = {}
    chsevs = {}
    rebootpkgs = []

    if args.tweaks:
        try:
            fh = open(args.tweaks, 'r')
            tweakdata = yaml.load(fh)
            fh.close()
            if 'definition_fixes' in tweakdata:
                deffixes = tweakdata['definition_fixes']
            if 'severity_changes' in tweakdata:
                chsevs = tweakdata['severity_changes']
            if args.needsreboot:
                if 'hint_reboot_packages' in tweakdata:
                    rebootpkgs = tweakdata['hint_reboot_packages']
                else:
                    rebootpkgs = ['kernel', 'glibc', 'linux-firmware',
                            'systemd', 'udev', 'openssl-libs', 'gnutls', 'nss',
                            'dbus']

        except Exception as ex:
            logger.info('Could not load tweaks from %s' % args.tweaks)
            sys.exit(0)

    main(args.vardir, args.factfile, args.defurl, deffixes, chsevs, rebootpkgs)