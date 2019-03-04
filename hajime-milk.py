#!/usr/bin/env python

import getopt
import os
import re
import subprocess
import sys
import tempfile
import time

USAGE = """
hajime_milk.py [options] [IP PORT] [PAYLOAD_NAME]

DESCRIPTION
  Attempts to download PAYLOAD_NAME from a Hajime bot listening for uTP
  connections on IP:PORT.  If the payload is downloaded, the payload header
  is parsed and the payload body is decompressed.

  Both the downloaded payload and the extracted file are saved.  The extracted
  payload is saved as PAYLOAD_NAME, and the file as PAYLOAD_NAME.file.  There
  are three exceptions to the naming of downloaded files.

    1.  As the config payload is the only payload whose name does not include
        the payload's creation timestamp, upon parsing the header (which contains a
        creation time field),, the original payload is renamed to
        config.<CREATION_TIME>, and the decompressed file to
        config.<CREATION_TIME>.file.  

    2.  Whereas a bot requests payloads of the form atk.<ARCH>.<CREATION_TIME>
        or .i.<ARCH>.<CREATION_TIME> the bots simply serve whatever payload they
        have that matches atk.<ARCH>. or .i.<ARCH>., disregarding the
        CREATION_TIME.  (Indeed, as along as a client requests 'atk.<ARCH>.' or
        '.i.<ARCH>.', the request is served).  If parsing the header of the
        payload reveals a different CREATION_TIME than the one requested, the
        downloaded payload and decompressed file's name are changed to reflect
        the correct TIMESTAMP.

    3. As .i files are 'hidden' files, the .i payload and decompressed file
       are renamed to __.i.<ARCH>.<TIMESTAMP>.

  If PAYLOAD_NAME is not given, it defaults to config.

  The --watch option is basically a poor man's way to monitor the
  kadnode/utp_key logs (which are quite large), and periodically attempt to
  download the payloads from the active bots.  Every period seconds (default
  60), the last 10 entries (IP:PORT) in the kadnode/utp_key log are tailed, and
  hajime_milk attempts to download PAYLOAD_NAME from these bots. The
  --directory, --follow, and --keep arguments apply.

  If --watch is given, then IP and PORT must not be specified; if --watch is
  not given, then IP and PORT must be specified.

  A typical invocation on the EC2 Hajime_GetKey nodes is:

    nohup ./hajime-milk.py -d p -f -k -w10:/home/ubuntu/logshards/cunny_lookup/:120 &

  or

    nohup ./hajime-milk.py -d p -f -k -w10:/home/ubuntu/logshards/hajime_large_lookup/:120 &


OPTIONS 
  -d, --directory DIRECTORY
    Save the payloads and extracted files to DIRECTORY (the default
    is the current directory). 

  -f, --follow ARCH
    If PAYLOAD_NAME is 'config' and -f is set, then, upon downloading the
    config file, attempt to download all other files listed in the config file
    for type ARCH.  If ARCH is 'all', then attempt to download all payloads
    listed in the config file.  (Note that bots only serve files that match
    their own architecture, so 'all' allows for cases where the user does
    not know the architecture of the remote bot's device.)

  -h, --help
    Show this help message and exit.

  -k, --keep
    If downloading the payload would overwrite a file of the same name, discard
    the downloaded payload and keep the original files.

  -w, --watch N:LOG_PATH:PERIOD
    Tail the last N lines from LOG_PATH every PERIOD seconds, and attempt to
    download from those bots.  If LOG_PATH is a directory, then the tailed file
    is LOG_PATH/yyyy-mm-dd.log in UTC, and yyyy-mm-dd changes automatially
    every UTC day.
""".strip()

DEVNULL = open(os.devnull, 'w')

def usage(exit_code=0):
    sys.stderr.write('%s\n' % USAGE)
    sys.exit(exit_code)

def get_config_module_entries(config_path):
    """"
    arguments
        config_path - the path to the config file

    returns
        a list of the payloads in the config's module section
    """
    in_modules = False
    modules = []
    with open(config_path) as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line.lower() == '[modules]':
                in_modules = True
                continue
            elif in_modules:
                if not re.match('\[\w+\]', line):
                    modules.append(line)
                else:
                    in_modules = False
    return modules

def hajime_parse_payload(ifile, ofile):
    """
    args:
        ifile - the input file (e.g., config)
        ofile - the ouptu fiel (e.g., config.file)

    returns
        on success, returns the creation time of the payload (an int).
        on failure, returns None
    """
    p = subprocess.Popen(args=['hajime_parse_payload', ifile, ofile],
            stderr=subprocess.PIPE)
    _, stderr = p.communicate()
    ctime = None
    for line in stderr.splitlines():
        line = line.strip()
        if line.startswith('creation_time: '):
            ctime = line.split()[1]
            ctime = int(ctime)
    return ctime

def hajime_getfile(ip, port, remote_file, local_file):
    """
    Download remote_file from bot listening on IP:PORT and save to local_file

    returns
        on success, returns True
        on failure, return False
    """
    # 3 sec non-activity (nothing to read on fd or time-to-connect) timeout
    # 6 sec total timeout
    p = subprocess.Popen(args=['timeout', '6', 'hajime_getfile', '-t', '3', ip, port,
        remote_file, local_file], stdout=DEVNULL, stderr=subprocess.STDOUT)
    p.communicate() # just ignore the output (but need to read it so that
                    # p.returncode is set)
    # the returncode for a time out is 124
    return True if p.returncode == 0 else False


def fix_payload_name(pname, ctime):
    if pname == 'config':
        fixed_pname = '%s.%s' % (pname, ctime)
    else:
        co = pname.split('.')
        prefix = ''
        if co[0] == '': 
            # rename payloads that are hidden files
            prefix = '__'
        if int(co[-1]) != ctime:
            fixed_pname = '%s%s.%s' % (prefix, '.'.join(co[:-1]), ctime)
        else:
            fixed_pname = '%s%s' % (prefix, pname)

    return fixed_pname


def hajime_get(ip, port, pname, directory, keep): 
    """
    returns (status, final_pname, final_fname) where
    status is True if the payload was downloaded and extracted, and False
    otherwise.  If status is False, final_pname, and final_fname are None.
    Otherwise, final_pname is the path to the downloaded payload, and
    final_fname is the path to the file that was extracted and decompressed
    from that payload.
    """
    # create final output directory
    if not os.path.exists(directory):
        os.mkdir(directory)

    # payload (pname) and extraced/decompresed file (fname) are
    # downloaded and unpacked in /tmp
    tmp_fd, tmp_pname = tempfile.mkstemp(prefix='hajime-payload')
    os.close(tmp_fd)
    tmp_fname = '%s.file' % tmp_pname

    # download the payload to /tmp 
    status = hajime_getfile(ip, port, pname, tmp_pname)
    if status is False or os.path.getsize(tmp_pname) == 0:
        sys.stderr.write('could not download %s\n' % pname)
        os.unlink(tmp_pname)
        return (False, None, None) 

    # parse the payload in /tmp
    ctime = hajime_parse_payload(tmp_pname, tmp_fname)
    if not ctime:
        sys.stderr.write('could not parse %s\n' % pname)
        os.unlink(tmp_pname)
        os.unlink(tmp_fname)
        return (False, None, None) 

    # fix names based on creation_time
    fixed_pname = fix_payload_name(pname, ctime)
    final_pname = os.path.join(directory, fixed_pname)
    final_fname = '%s.file' % final_pname 

    # move the file to the output directory (or, if user specified
    # not to overwrite existing files, simply delete the files we just
    # downloaded and extracted.
    if not os.path.exists(final_pname) or not keep:
        os.rename(tmp_pname, final_pname)
    else:
        sys.stderr.write('%s already exists; not overwriting\n' % final_pname)
        os.unlink(tmp_pname)

    if not os.path.exists(final_fname) or not keep:
        os.rename(tmp_fname, final_fname)
    else:
        sys.stderr.write('%s already exists; not overwriting\n' % final_fname)
        os.unlink(tmp_fname)

    return (True, final_pname, final_fname)


def do_one(ip, port, pname, directory, keep, follow, arch):
    print 'do_one(%s, %s, %s, %s, %s)\n' % (ip, port, pname, directory, keep)
    status, final_pname, final_fname = hajime_get(ip, port, pname, directory, keep)
    if not status:
        sys.exit(1)

    if pname == 'config' and follow:
        modules = get_config_module_entries(final_fname)
        for module in modules:
            if (arch.lower() != 'all') and (arch not in module):
                continue
            sys.stderr.write('attempting to download module `%s\n' % module)
            hajime_get(ip, port, module, directory, keep)

    sys.exit(0)


def do_watch(pname, directory, keep, follow, arch, watch_lines, watch_path, watch_period): 
    print 'do_watch(%s, %s, %s, %s, %s, %d, %s, %d)\n' % (pname, directory, keep,
            follow, arch, watch_lines, watch_path, watch_period)

    watch_file = watch_path
    keywords = ('config', 'mipseb', 'mipsel', 'arm5', 'arm6', 'arm7')

    while True:
        for keyword in keywords:

            if os.path.isdir(watch_path):
                now = time.time()
                tup = time.gmtime(now)
                watch_file = os.path.join(watch_path, time.strftime('%Y-%m-%d.log', tup))

            cmd = "grep %s %s | tail -n%d | awk '{ print $6,$7 }'" % (keyword, watch_file, watch_lines)

            try:
                output = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as e:
                sys.stderr.write('subprocess.check_output failed: %s' % str(e))
                time.sleep(30)
                continue

            if not output:
                time.sleep(30)

            for line in output.splitlines():
                line = line.strip()
                ip, port = line.split()
                status, final_pname, final_fname = hajime_get(ip, port, pname, directory, keep)
                if not status:
                    continue

                if pname == 'config' and follow:
                    modules = get_config_module_entries(final_fname)
                    for module in modules:
                        if (arch.lower() != 'all') and (arch not in module):
                            continue
                        sys.stderr.write('attempting to download module `%s\n' % module)
                        hajime_get(ip, port, module, directory, keep)


# changes in other tools:
#   [x] need to change hajime_getfile to accept timeout option (-t)
#
#   [x] need to change hajime_parse_payload to use offset for -12 for config
#       and -8 for executables (atk's and .i's)
#
#       check what status code hajime_getfile returns (particularly in the case
#       of a time, as well as what status code hajime_parse_payload returns if
#       there is a parsing error.
#   
#       need an option to monitor a file or monitor a directory; I'm not
#       envisioning anythin fancy; just something that sits in a loop, runs
#       tail -25 on a a file every so often, and just iterates over the IP
#       addresses and ports, attempting to download (and follow) config from
#       the bot at each address.
#
# other changes (not clear which tool) should implement:
#   - if a payload is not downloaded, the 0 size file must be deleted

def main(argv):
    shortopts = 'd:f:hkw:'
    longopts = ['directory=', 'follow=', 'help', 'keep', 'watch=']

    directory = os.getcwd()
    keep = False
    follow = False
    arch = None

    watch = False
    watch_lines = None
    watch_path = None
    watch_period = None

    pname = 'config'

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n' % err)
        usage(1)

    for o, a in opts:
        if o in ('-d', '--directory'):
            directory = a
        elif o in ('-f', '--follow'):
            follow = True
            arch = a
        elif o in ('-h', '--help'):
            usage(0)
        elif o in ('-k', '--keep'):
            keep = True
        elif o in ('-w', '--watch'):
            p = a.split(':')
            if len(p) != 3:
                sys.stderr.write('invalid value for the --watch option: %s\n' % a)
                usage(1)
            watch = True
            watch_lines, watch_path, watch_period = int(p[0]), p[1], int(p[2])
        else:
            assert False, "unhandled option '%s'" % o

    if not watch:
        if len(args) < 2 or len(args) > 3: 
            sys.stderr.write('when --watch is not specified, IP, PORT, and (optionally) PAYLOAD_NAME, must be specified\n')
            usage(1)
        ip = args[0]
        port = args[1]
        if len(args) == 3:
            pname = args[2]
        do_one(ip, port, pname, directory, keep, follow, arch)
    else:
        if len(args) > 1:
            sys.stderr.write('when --watch is specified, only PAYLOAD_NAME may (optionally) be specified\n')
            usage(1)
        if len(args) == 1:
            pname = args[0]
        do_watch(pname, directory, keep, follow, arch, watch_lines, watch_path, watch_period)


if __name__ == '__main__':
    main(sys.argv)
