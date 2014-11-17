#coding: UTF-8
__author__ = 'yangchenxing'

import argparse
import collections
import functools
import itertools
import os
import requests
import signal
import sys

import supervisor.events
import supervisor.supervisorctl
import supervisor.supervisord


app_config = {
    'workdir': os.path.join(os.path.dirname(sys.argv[0]), os.path.pardir),
    'programs': {
        'test_program': {
            'command': 'python test/test_program.py',
            'process_name': 'TestProgram'
        }
    },
    'eventlistener': {
        'command': 'python %s listen' % (sys.argv[0],),
        'process_name': os.path.splitext(os.path.basename(sys.argv[0]))[0] + '_eventlistener',
        'events': [
            'PROCESS_STATE_EXITED',
        ],
        'event_handlers': {
            'PROCESS_STATE_EXITED': {
                'notifier_type': 'simple_mail',
                'receivers': [
                    'jedidiahyang@jesgoo.com'
                ]
            },
        },
        'notification_server': {
            'host': '127.0.0.1',
            'port': 8080,
            'simplemail': 'simplemail'
        }
    }
}


class ApplicationConfig(object):
    def __init__(self, **conf):
        self._conf = conf

    def __call__(self, *names):
        return reduce(lambda x, y: None if x is None else (x[y] if y in x else None), names, self._conf)

    def __getattr__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        return self.__dict__['_conf'].get(item, None)


app_config = ApplicationConfig(**app_config)


def start(args):
    if args.args:
        app_config('programs').values()[0]['command'] += ' ' + ' '.join(args.args)
    config = merge_config()
    with open(args.supervisord_config_path, 'w') as f:
        dump_config(config, f)
        print '导出配置完成'
    if os.path.exists(config['supervisord']['pidfile'][1]):
        with open(config['supervisord']['pidfile'][1], 'r') as f:
            pid = int(f.read())
        try:
            os.kill(pid, signal.SIG_DFL)
            process_exists = True
        except OSError:
            process_exists = False
    else:
        process_exists = False
    if process_exists:
        reload(args)
    else:
        supervisor.supervisord.main(args=['-c', args.supervisord_config_path])


def stop(args):
    supervisor.supervisorctl.main(args=['-c', args.supervisord_config_path, 'stop', 'all'])


def status(args):
    supervisor.supervisorctl.main(args=['-c', args.supervisord_config_path, 'status'])


def reload(args):
    supervisor.supervisorctl.main(args=['-c', args.supervisord_config_path, 'reload'])


def listen(args):
    listener = app_config('eventlistener')
    listener = EventListener(event_handlers=listener['event_handlers'],
                             notification_server=listener['notification_server'])
    listener.run()


def kill(args):
    config = merge_config()
    if os.path.exists(config['supervisord']['pidfile'][1]):
        with open(config['supervisord']['pidfile'][1], 'r') as f:
            pid = int(f.read())
        try:
            os.kill(pid, signal.SIGTERM)
            print '进程已经杀死'
        except OSError:
            print '进程不存在'
    else:
        print 'PID文件不存在'


operations = {
    'start': start,
    'stop': stop,
    'status': status,
    'listen': listen,
    'kill': kill,
}


default_supervisord_config = collections.OrderedDict([
    ('__doc__', 'Sample supervisor config file.\n' +
                '\n' +
                'For more information on the config file, please see:\n' +
                'http://supervisord.org/configuration.html\n' +
                '\n' +
                'Notes:\n' +
                '  - Shell expansion ("~" or "$HOME") is not supported.  Environment\n' +
                '    variables can be expanded using this syntax: "%(ENV_HOME)s".\n' +
                '  - Comments must have a leading space: "a=b ;comment" not "a=b;comment".'),
    ('unix_http_server', collections.OrderedDict([
        ('__enabled__', True),
        ('file', (True, 'logs/supervisord.sock', '(the path to the socket file)')),
        ('chmod', (False, 0700, 'socket file mode (default 0700)')),
        ('chown', (False, 'nobody:nogroup', 'socket file uid:gid owner')),
        ('username', (False, 'user', '(default is no username (open server))')),
        ('password', (False, 123, '(default is no password (open server))')),
    ])),
    ('inet_http_server', collections.OrderedDict([
        ('__enabled__', False),
        ('port', (False, '127.0.0.1:9001', '(ip_address:port specifier, *:port for all iface)')),
        ('username', (False, 'user', '(default is no username (open server))')),
        ('password', (False, '123', '(default is no password (open server))')),
    ])),
    ('supervisord', collections.OrderedDict([
        ('logfile', (True, 'logs/supervisord.log', '(main log file;default $CWD/supervisord.log)')),
        ('logfile_maxbytes', (True, '50MB', '(max main logfile bytes b4 rotation;default 50MB)')),
        ('logfile_backups', (True, 10, '(num of main logfile rotation backups;default 10)')),
        ('loglevel', (True, 'info', '(log level;default info; others: debug,warn,trace)')),
        ('pidfile', (True, 'logs/supervisord.pid', '(supervisord pidfile;default supervisord.pid)')),
        ('nodaemon', (True, False, '(start in foreground if true;default false)')),
        ('minfds', (True, 1024, '(min. avail startup file descriptors;default 1024)')),
        ('minprocs', (True, 200, '(min. avail process descriptors;default 200)')),
        ('umask', (False, 022, '(process file creation umask;default 022)')),
        ('user', (False, 'chrism', '(default is current user, required if root)')),
        ('identifier', (False, 'supervisor', '(supervisord identifier, default is \'supervisor\')')),
        ('directory', (False, '/tmp', '(default is not to cd during start)')),
        ('nocleanup', (False, True, '(don\'t clean up tempfiles at start;default false)')),
        ('childlogdir', (False, '/tmp', '(\'AUTO\' child log dir, default $TEMP)')),
        ('environment', (False, 'KEY="value"', '(key value pairs to add to environment)')),
        ('strip_ansi', (False, False, '(strip ansi escape codes in logs; def. false)')),
    ])),
    ('rpcinterface', collections.OrderedDict([
        ('__example__', 'supervisor'),
        ('supervisor.rpcinterface_factory', (True, 'supervisor.rpcinterface:make_main_rpcinterface', '')),
    ])),
    ('supervisorctl', collections.OrderedDict([
        ('serverurl', (True, 'unix://logs/supervisord.sock', 'use a unix:// URL  for a unix socket')),
        ('username', (False, 'chris', 'should be same as http_username if set')),
        ('password', (False, '123', 'should be same as http_password if set')),
        ('prompt', (False, 'mysupervisor', 'cmd line prompt (default "supervisor")')),
        ('history_file', (False, '~/.sc_history', 'use readline history if available')),
    ])),
    ('program', collections.OrderedDict([
        ('command', (True, 'bin/program', 'the program (relative uses PATH, can take args)')),
        ('process_name', (False, '%(program_name)s', 'process_name expr (default %(program_name)s)')),
        ('numprocs', (False, 1, 'number of processes copies to start (def 1)')),
        ('directory', (False, '/tmp', 'directory to cwd to before exec (def no cwd)')),
        ('umask', (False, 022, 'umask for process (default None)')),
        ('priority', (False, 999, 'the relative start priority (default 999)')),
        ('autostart', (False, True, 'start at supervisord start (default: true)')),
        ('autorestart', (False, 'unexpected', 'whether/when to restart (default: unexpected)')),
        ('startsecs', (False, 1, 'number of secs prog must stay running (def. 1)')),
        ('tartretries', (False, 3, 'max # of serial start failures (default 3)')),
        ('xitcodes', (False, 0, '\'expected\' exit codes for process (default 0,2)')),
        ('topsignal', (False, 'TERM', 'signal used to kill process (default TERM)')),
        ('topwaitsecs', (False, 5, 'max num secs to wait b4 SIGKILL (default 10)')),
        ('stopasgroup', (False, False, 'send stop signal to the UNIX process group (default false)')),
        ('killasgroup', (False, False, 'SIGKILL the UNIX process group (def false)')),
        ('user', (False, 'chrism', 'setuid to this UNIX account to run the program')),
        ('redirect_stderr', (False, True, 'redirect proc stderr to stdout (default false)')),
        ('stdout_logfile', (True, 'logs/supervisord.stdout.log', 'stdout log path, NONE for none; default AUTO')),
        ('stdout_logfile_maxbytes', (True, '1MB', 'max # logfile bytes b4 rotation (default 50MB)')),
        ('stdout_logfile_backups', (True, 10, '# of stdout logfile backups (default 10)')),
        ('stdout_capture_maxbytes', (False, '1MB', 'number of bytes in \'capturemode\' (default 0)')),
        ('stdout_events_enabled', (True, True, 'emit events on stdout writes (default false)')),
        ('stderr_logfile', (True, 'logs/supervisord.stderr.log', 'stderr log path, NONE for none; default AUTO')),
        ('stderr_logfile_maxbytes', (True, '1MB', 'max # logfile bytes b4 rotation (default 50MB)')),
        ('stderr_logfile_backups', (True, 10, '# of stderr logfile backups (default 10)')),
        ('stderr_capture_maxbytes', (False, '1MB', 'number of bytes in \'capturemode\' (default 0)')),
        ('stderr_events_enabled', (True, True, 'emit events on stderr writes (default false)')),
        ('environment', (False, 'A="1",B="2"', 'process environment additions (def no adds)')),
        ('serverurl', (False, 'AUTO', 'override serverurl computation (childutils)')),
    ])),
    ('eventlistener', collections.OrderedDict([
        ('__enabled__', False),
        ('__doc__', 'The below sample group section shows all possible group values,\n' +
                    'create one or more \'real\' group: sections to create "heterogeneous"\n' +
                    'process groups.'),
        ('__example__', 'theeventlistenername'),
        ('command', (False, '/bin/eventlistener', 'the program (relative uses PATH, can take args)')),
        ('process_name', (False, '%(program_name)s', 'process_name expr (default %(program_name)s)')),
        ('numprocs', (False, 1, 'number of processes copies to start (def 1)')),
        ('events', (False, 'EVENT', 'event notif. types to subscribe to (req\'d)')),
        ('buffer_size', (False, 10, 'event buffer queue size (default 10)')),
        ('directory', (False, '/tmp', 'directory to cwd to before exec (def no cwd)')),
        ('umask', (False, 022, 'umask for process (default None)')),
        ('priority', (False, -1, 'the relative start priority (default -1)')),
        ('autostart', (False, True, 'start at supervisord start (default: true)')),
        ('autorestart', (False, 'unexpected', 'whether/when to restart (default: unexpected)')),
        ('startsecs', (False, 1, 'number of secs prog must stay running (def. 1)')),
        ('startretries', (False, 3, 'max # of serial start failures (default 3)')),
        ('exitcodes', (False, [0, 2], '\'expected\' exit codes for process (default 0,2)')),
        ('stopsignal', (False, 'QUIT', 'signal used to kill process (default TERM)')),
        ('stopwaitsecs', (False, 10, 'max num secs to wait b4 SIGKILL (default 10)')),
        ('stopasgroup', (False, False, 'send stop signal to the UNIX process group (default false)')),
        ('killasgroup', (False, False, 'SIGKILL the UNIX process group (def false)')),
        ('user', (False, 'chrism', 'setuid to this UNIX account to run the program')),
        ('redirect_stderr', (False, True, 'redirect proc stderr to stdout (default false)')),
        ('stdout_logfile', (True, 'logs/supervisord.eventlistener.stdout.log', 'stdout log path, NONE for none; default AUTO')),
        ('stdout_logfile_maxbytes', (True, '50MB', 'max # logfile bytes b4 rotation (default 50MB)')),
        ('stdout_logfile_backups', (True, 10, '# of stdout logfile backups (default 10)')),
        ('stdout_events_enabled', (False, True, 'emit events on stdout writes (default false)')),
        ('stderr_logfile', (True, 'logs/supervisord.eventlistener.stderr.log', 'stderr log path, NONE for none; default AUTO')),
        ('stderr_logfile_maxbytes', (True, '50MB', 'max # logfile bytes b4 rotation (default 50MB)')),
        ('stderr_logfile_backups', (True, 10, '# of stderr logfile backups (default 10)')),
        ('stderr_events_enabled', (False, True, 'emit events on stderr writes (default false)')),
        ('environment', (False, 'A="1",B="2"', 'process environment additions')),
        ('serverurl', (False, 'AUTO', 'override serverurl computation (childutils)')),
    ])),
    ('group', collections.OrderedDict([
        ('__enabled__', False),
        ('__doc__', 'The below sample group section shows all possible group values,\n' +
                    'create one or more \'real\' group: sections to create "heterogeneous"\n' +
                    'process groups.'),
        ('__example__', 'thegroupname'),
        ('programs', (False, ['progname1', 'progname2'], 'each refers to \'x\' in [program:x] definitions')),
        ('priority', (False, 999, 'the relative start priority (default 999)')),
    ])),
    ('include', collections.OrderedDict([
        ('__enabled__', False),
        ('__doc__', 'The [include] section can just contain the "files" setting.  This\n' +
                    'setting can list multiple files (separated by whitespace or\n' +
                    'newlines).  It can also contain wildcards.  The filenames are\n' +
                    'interpreted as relative to this file.  Included files *cannot*\n' +
                    'include files themselves.'),
        ('files', (False, ['relative/directory/*.ini'], ''))
    ]))
])


def dump_doc(stream, doc):
    if doc is None:
        return
    for line in doc.split('\n'):
        print >>stream, ';', line
    print >>stream


def format_option_value(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (tuple, list)):
        return ','.join(map(format_option_value, value))
    if isinstance(value, str):
        return value
    raise ValueError('不支持的选项类型：%s', type(value))


def dump_section(stream, name, options, doc=None, enabled=False):
    if doc is not None:
        dump_doc(stream, doc)
    if enabled:
        print >>stream, '[%s]' % (name,)
    else:
        print >>stream, ';[%s]' % (name,)
    options = [(option_name, option_enabled and enabled, format_option_value(option_value), option_doc)
               for option_name, (option_enabled, option_value, option_doc) in options.iteritems()]
    max_option_length = max(itertools.imap(lambda x: len(x[2]) + len(x[0]) + (1 if enabled else 2), options))
    for name, enabled, value, doc in options:
        if enabled:
            option = '%s=%s' % (name, value)
        else:
            option = ';%s=%s' % (name, value)
        if doc:
            print >>stream, option, ' ' * (max_option_length - len(option)) + '; %s' % (doc,)
        else:
            print >>stream, option
    print >>stream


def dump_config(config, stream):
    dump_doc(stream, default_supervisord_config.get('__doc__', None))
    for name, section in config.iteritems():
        if name.startswith('__'):
            continue
        options = section.copy()
        doc = section.get('__doc__', None)
        enabled = section.get('__enabled__', True)
        for option_name in itertools.ifilter(lambda x: x.startswith('__'), section.keys()):
            del options[option_name]
        dump_section(stream, name, options, doc=doc, enabled=enabled)


def merge_section_config(default_config, user_config):
    config = collections.OrderedDict()
    for key, value in default_supervisord_config[default_config].iteritems():
        if key == '__enabled__':
            config[key] = user_config.get('__enabled__', True) if user_config else value
        elif key.startswith('__') or not user_config or key not in user_config:
            config[key] = value
        else:
            config[key] = (True, user_config[key], value[2])
    return config


def set_named_section(config, section_type, section_name=None, options=None):
    if section_name is None:
        section_options = default_supervisord_config[section_type]
        section_name = section_options['__example__']
    else:
        options['__enabled__'] = True
    config[section_type + ':' + section_name] = merge_section_config(section_type, options)


def merge_config():
    config = collections.OrderedDict()
    if '__doc__' in default_supervisord_config:
        config['__doc__'] = default_supervisord_config['__doc__']
    config['unix_http_server'] = merge_section_config('unix_http_server', app_config('supervisord', 'unix_http_server'))
    config['inet_http_server'] = merge_section_config('inet_http_server', app_config('supervisord', 'inet_http_server'))
    config['supervisord'] = merge_section_config('supervisord', app_config('supervisord', 'supervisord'))
    rpcinterfaces = app_config('supervisord', 'rpcinterfaces')
    if rpcinterfaces:
        for rpcinterface_name, rpcinterface_options in rpcinterfaces.iteritems():
            set_named_section(config, 'rpcinterface', rpcinterface_name, rpcinterface_options)
    else:
        set_named_section(config, 'rpcinterface')
    config['supervisorctl'] = merge_section_config('supervisorctl', app_config('supervisord', 'supervisorctl'))
    programs = app_config('programs')
    if programs:
        for program_name, program_options in programs.iteritems():
            set_named_section(config, 'program', program_name, program_options)
    else:
        set_named_section(config, 'program')
    listener = app_config('eventlistener')
    if listener:
        set_named_section(config, 'eventlistener', listener.get('name', 'event_listener'), listener)
    else:
        set_named_section(config, 'eventlistener')
    groups = app_config('groups')
    if groups:
        for group_name, group_options in groups:
            set_named_section(config, 'group', group_name, group_options)
    else:
        set_named_section(config, 'group')
    config['include'] = merge_section_config('include', app_config('supervisord', 'include'))
    return config


class EventHeader(object):
    def _to_int(self, item):
        if item in self._headers:
            self._headers[item] = int(self._headers[item])

    def __init__(self, text):
        self._headers = dict(head.split(':', 1) for head in text.rstrip('\n').split(' ') if ':' in head)
        self._to_int('serial')
        self._to_int('poolserial')
        self._to_int('len')

    @property
    def dict(self):
        return self._headers

    def __getattr__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        return self.__dict__['_headers'].get(item, None)


class EventBody(object):
    def __init__(self, text):
        attributes, data = text.split('\n', 1)
        self._headers = dict(head.split(':', 1) for head in attributes.split(' ') if ':' in head)
        self._data = data

    @property
    def dict(self):
        result = self._headers.copy()
        result['data'] = self._data
        return result


class EventListener(object):
    def __init__(self, event_handlers, notification_server):
        self._handler = dict(map(lambda x: (x[0], self._make_notifier(**x[1])),
                                 filter(lambda x: x[0] in dir(supervisor.events.EventTypes),
                                        event_handlers.iteritems())))
        self._simple_mail_url = 'http://%(host)s:%(port)d/%(simplemail)s' % notification_server

    @staticmethod
    def _write_stdout(text):
        sys.stdout.write(text)
        sys.stdout.flush()

    @staticmethod
    def _write_stderr(text):
        sys.stderr.write(text)
        sys.stderr.flush()

    def run(self):
        try:
            while 1:
                self._write_stdout('READY\n')
                header_line = sys.stdin.readline()
                self._write_stderr(header_line)
                header = EventHeader(header_line)
                body_length = header.len
                if body_length is None:
                    self._write_stderr('[ERROR] 缺少事件内容长度，不读取内容，跳过此条事件\n')
                    continue
                body_content = sys.stdin.read(int(body_length))
                self._write_stderr(body_content)
                body = EventHeader(body_content)
                if header.eventname is None:
                    self._write_stderr('[ERROR] 缺少事件名称，事件头部: %s\n' % (str(header_line),))
                    continue
                handler = self._handler.get(header.eventname, None)
                if handler:
                    ok, error = handler(event_header=header, event_body=body)
                    if not ok:
                        self._write_stderr('[ERROR] 处理事件失败: %s\n' % (error,))
                self._write_stdout('READY\n')
        except KeyboardInterrupt:
            pass
        except SystemExit:
            pass

    def _make_notifier(self, notifier_type, **kwargs):
        if notifier_type == 'simple_mail':
            return functools.partial(self._notify_simple_mail, **kwargs)
        if notifier_type == 'relay_stdout':
            return self._relay_stdout
        if notifier_type == 'relay_stderr':
            return self._relay_stderr

    def _notify_simple_mail(self, event_header, event_body,
                            receivers, carbon_copy=None, blind_carbon_copy=None,
                            subject=None, message=None):
        params = {}
        params.update(event_header.dict)
        params.update(event_body.dict)
        query = {}
        query['to'] = ','.join(receivers)
        query['sub'] = (subject if subject else 'Supervisord Event %(eventname)s') % params
        query['msg'] = (message if message else '') % params
        if carbon_copy:
            query['cc'] = ','.join(carbon_copy)
        if blind_carbon_copy:
            query['bcc'] = ','.join(blind_carbon_copy)
        response = requests.get(self._simple_mail_url, params=query)
        return (response.status_code == requests.codes.ok), response.text

    def _relay_stdout(self, event_header, event_body):
        print >>sys.stdout, event_body.data

    def _relay_stderr(self, event_header, event_body):
        print >>sys.stderr, event_body.data


def parse_args():
    parser = argparse.ArgumentParser(description='捷酷Supervisor实用程序')
    parser.add_argument('--supervisord-config',
                        dest='supervisord_config_path',
                        default='conf/supervisord.conf',
                        help='Supervisord配置文件导出路径')
    subparsers = parser.add_subparsers(dest='operation', help='操作')
    subparser = subparsers.add_parser('start', help='启动服务')
    subparser.add_argument('args', nargs='*', help='命令行参数')
    subparser = subparsers.add_parser('stop', help='停止')
    subparser = subparsers.add_parser('status', help='查看状态')
    subparser = subparsers.add_parser('listen', help='事件监听')
    subparser = subparsers.add_parser('kill', help='杀死Supvervisord进程')
    return parser.parse_args()


def main(args=None):
    if args is None:
        args = parse_args()
    operations[args.operation](args)


if __name__ == '__main__':
    os.chdir(app_config.workdir)
    main()