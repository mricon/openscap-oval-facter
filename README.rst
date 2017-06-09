Openscap Oval Facter
====================

This is a small utility to translate openscap OVAL policy analysis
results into a YAML file of puppet facts that can be queried via the
puppet dashboard or via an orchestration tool (like MCO).

Requirements
------------
Requires the following packages to be installed:

- openscap-scanner
- python-requests
- python-lxml
- PyYAML

Example usage
-------------
When run with --help::

    usage: openscap-oval-facter.py [-h] [--vardir VARDIR] [--factfile FACTFILE]
                                   [--defurl DEFURL] [--logfile LOGFILE]
                                   [--sleep SLEEP] [--quiet] [--tweaks TWEAKS]
                                   [--needsreboot]

    Convert oval results into puppet facts

    optional arguments:
      -h, --help           show this help message and exit
      --vardir VARDIR      where to keep intermediate files (/var/lib/openscap)
      --factfile FACTFILE  where to write the resulting yaml
                           (/etc/puppetlabs/facter/facts.d/openscap.yaml)
      --defurl DEFURL      url with oval definitions
      --logfile LOGFILE    log things into this logfile (/var/log/openscap-oval-
                           facter.log)
      --sleep SLEEP        randomly sleep up to this many seconds
      --quiet              only output critical errors
      --tweaks TWEAKS      Yaml file with definition tweaks and overrides
      --needsreboot        Hint if a system needs a reboot

Example cron invocation for an EL7 system::

  /usr/local/bin/openscap-oval-facter.py \
    --vardir /var/lib/openscap \
    --factfile /etc/puppetlabs/facter/facts.d/openscap.yaml \
    --defurl https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_7.xml \
    --tweaks /etc/openscap/tweaks.yaml \
    --needsreboot --quiet --sleep 300

See the "example-tweaks.yaml" file for some detail on what can be
tweaked in the upstream oval XML policy file to make it work on your
system, or to upgrade/downgrade severity on some errata.

You will probably be running this from cron, so we add a `--sleep`
parameter to help make sure not all systems are hitting the definitions
file at once, plus suppress output with `--quiet`.

The `--needsreboot` parameter requires yum libraries to work and will
help you pinpoint when a system needs rebooting in order to enable the
updated kernel or some core libraries.

Output
------
See example-facts.yaml for a real output example from a CentOS 7 system
that needs a good patching.

Limitations
-----------
This will ONLY provide vulnerability tracking for core packages provided
by Red Hat (and rebuilt by CentOS). If you installed custom packages or
anything from EPEL, any vulnerabilities in that software will be
completely missed by this tool.
