__description__ = "a plugin to help you understand java world."

import json
import os
import time

import click

from objection.utils.plugin import Plugin
from objection.state.connection import state_connection


class DvmDescConverter:
    def __init__(self, desc):
        self.dvm_desc = desc

    def to_java(self):
        result = str(self.dvm_desc)
        result = result.strip()
        dim = 0
        while result.startswith('['):
            result = result[1:]
            dim += 1

        if result.startswith('L') and result.endswith(';'):
            result = result[1: -1]

        result = result.replace('/', '.')

        result += "[]" * dim
        return result

    def short_name(self):
        result = self.to_java()
        if '.' in result:
            result = result[result.rindex(".") + 1:]
        return result


class WallBreaker(Plugin):

    def __init__(self, ns):
        self.script_path = os.path.join(os.path.dirname(__file__), "agent/_agent.js")
        self.on_message_handler = self.on_message
        self.object_classes = {}

        implementation = {
            'meta': 'help you understand java world.',
            'commands': {
                'classdump': {
                    'meta': 'quick view a class struct',
                    'flags': ['--fullname'],
                    'exec': self.classdump
                },
                'classsearch': {
                    'meta': 'search class by pattern',
                    'flags': [],
                    'exec': self.classsearch
                },
                'objectdump': {
                    'meta': 'quick view an object internal',
                    'flags': ['--fullname', "--as-class"],
                    'exec': self.objectdump
                },
                'objectsearch': {
                    'meta': 'search instance in heap',
                    'flags': [],
                    'exec': self.objectsearch
                }
            }
        }

        super().__init__(__file__, ns, implementation)

        self.script_src = None

    def inject(self):
        self._prepare_source()
        if not self.script_src:
            raise Exception('Unable to discover Frida script source to inject')

        if not self.agent:
            self.agent = state_connection.get_agent()

        self.session = self.agent.session
        if not self.session:
            raise Exception('Unable to discover Objection Frida session')

        self.script = self.session.create_script(source=self.script_src)
        self.script.on('message', self.on_message_handler if self.on_message_handler else self.agent.handlers.script_on_message)
        self.script.load()
        self.api = self.script.exports

    def ensure_injected(self):
        if self.api:
            return

        click.secho("[wallbreaker] injecting agent...", fg="bright_black")
        time.sleep(1)
        self.inject()

    def on_message(self, message, data):
        if message.get('type') == 'send':
            payload = message.get('payload')
            if isinstance(payload, dict) and payload.get('type') == 'wallbreaker-debug':
                click.secho(
                    "[wallbreaker-agent] {} {}".format(
                        payload.get('event'),
                        json.dumps(payload.get('detail', {}), ensure_ascii=False)
                    ),
                    fg="bright_black"
                )
                return
            click.secho("(agent) {}".format(payload))
            return

        click.secho("[wallbreaker-agent] {}".format(message), fg="yellow")

    def classdump(self, args=None):
        self.ensure_injected()
        short_name = True
        target_name = ""
        for arg in args:
            if arg == "--fullname":
                short_name = False
            else:
                target_name = arg

        click.secho("[wallbreaker] classdump target: {}".format(target_name), fg="bright_black")
        self._class_dump(target_name, pretty_print=True, short_name=short_name)

    def classsearch(self, args=None):
        pattern = args[0]
        click.secho("[wallbreaker] classsearch pattern: {}".format(pattern), fg="bright_black")
        instances = self._class_match(pattern)
        click.secho("[wallbreaker] matched classes: {}".format(len(instances)), fg="bright_black")
        if instances:
            print("\n".join(instances))
        else:
            click.secho("[wallbreaker] no matched loaded classes.", fg="yellow")

    def objectdump(self, args=None):
        short_name = True
        as_class = None
        handle = ""
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--fullname":
                short_name = False
            elif arg == "--as-class":
                as_class = args[idx + 1]
                idx += 1
            else:
                handle = arg
            idx += 1

        self._object_dump(handle, as_class=as_class, pretty_print=True, short_name=short_name)

    def objectsearch(self, args=None):
        clsname = args[0]
        instances = self._object_search(clsname)
        for handle in instances:
            print("[{}]: {}".format(handle, instances[handle]))

    def _class_match(self, pattern):
        try:
            results = state_connection.get_api().android_hooking_enumerate(pattern)
            classes = []
            seen = set()
            for result in results:
                for clazz in result.get('classes', []):
                    name = clazz.get('name')
                    if name and name not in seen:
                        seen.add(name)
                        classes.append(name)
            return sorted(classes)
        except Exception as e:
            click.secho(
                "[wallbreaker] objection class enumerate failed, falling back to wallbreaker agent: {}".format(e),
                fg="yellow"
            )
            self.ensure_injected()
            return self.api.class_match(pattern)

    def _class_use(self, name):
        target = json.loads(self.api.class_use(name))
        click.secho(
            "[wallbreaker] class_use result: name={}, ctors={}, static_methods={}, instance_methods={}, static_fields={}, instance_fields={}".format(
                target.get('name'),
                len(target.get('constructors', [])),
                len(target.get('staticMethods', {})),
                len(target.get('instanceMethods', {})),
                len(target.get('staticFields', {})),
                len(target.get('instanceFields', {}))
            ),
            fg="bright_black"
        )
        return target

    def _object_get_classname(self, handle):
        if str(handle) in self.object_classes:
            return self.object_classes[str(handle)]
        return self.api.object_get_class(handle)

    def _object_get_field(self, handle, field, as_class=None):
        return self.api.object_get_field(handle, field, as_class)

    def _object_search(self, clsname):
        try:
            objects = state_connection.get_api().android_heap_get_live_class_instances(clsname)
            results = {}
            for obj in objects:
                handle = str(obj.get('hashcode'))
                self.object_classes[handle] = obj.get('classname') or clsname
                results[handle] = obj.get('tostring')
            return results
        except Exception as e:
            click.secho(
                "[wallbreaker] objection heap search failed, falling back to wallbreaker agent: {}".format(e),
                fg="yellow"
            )
            self.ensure_injected()
            return self.api.object_search(clsname, False)

    def _class_dump(self, name, handle=None, pretty_print=False, short_name=True):
        target = self._class_use(name)
        result = ""
        if pretty_print:
            click.secho("")
        class_name = str(target['name'])
        if '.' in class_name:
            pkg = class_name[:class_name.rindex('.')]
            class_name = class_name[class_name.rindex('.') + 1:]
            result += "package {};\n\n".format(pkg)
            if pretty_print:
                click.secho("package ", fg="blue", nl=False)
                click.secho(pkg + "\n\n", nl=False)

        result += "class {}".format(class_name) + " {\n\n"
        if pretty_print:
            click.secho("class ", fg="blue", nl=False)
            click.secho(class_name, nl=False)
            click.secho(" {\n\n", fg='red', nl=False)

        def handle_fields(fields, can_preview=None):
            _handle = handle
            if can_preview is None:
                can_preview = _handle is not None
            elif can_preview and _handle is None:
                _handle = target['name']
            append = ""
            original_class = None if handle is None else self._object_get_classname(handle)
            for field in fields:
                try:
                    field = field[0]
                    t = DvmDescConverter(field['type'])
                    t = t.short_name() if short_name else t.to_java()
                    append += '\t'
                    if pretty_print:
                        click.secho("\t", nl=False)
                    append += "static " if field['isStatic'] else ""
                    if pretty_print:
                        click.secho("static " if field['isStatic'] else "", fg='blue', nl=False)
                    append += t + " "
                    if pretty_print:
                        click.secho(t + " ", fg='blue', nl=False)

                    value = None
                    if can_preview:
                        value = self._object_get_field(handle=_handle,
                                                       field=field['name'],
                                                       as_class=name if original_class and original_class != name else None)
                    append += '{};{}\n'.format(field["name"], " => {}".format(value) if value is not None else "")
                    if pretty_print:
                        click.secho(field['name'], fg='red', nl=False)
                        click.secho(";", nl=False)
                        if value is not None:
                            click.secho(" => ", nl=False)
                            click.secho(value, fg='bright_cyan', nl=False)
                        click.secho("")
                except:
                    append += "<unknown error>\n"
                    if pretty_print:
                        click.secho("<unknown error>", fg="red", nl=False)
                        click.secho()

            append += '\n'
            if pretty_print: click.secho("\n", nl=False)
            return append

        static_fields = target['staticFields']
        instance_fields = target['instanceFields']

        result += "\t/* static fields */\n"
        if pretty_print:
            click.secho("\t/* static fields */", fg="bright_black")
        result += handle_fields(static_fields.values(), can_preview=True)

        result += "\t/* instance fields */\n"
        if pretty_print:
            click.secho("\t/* instance fields */", fg="bright_black")
        result += handle_fields(instance_fields.values())

        def handle_methods(methods):
            append = ""
            for method in methods:
                try:
                    if short_name:
                        args_s = [DvmDescConverter(arg).short_name() for arg in method['arguments']]
                    else:
                        args_s = [DvmDescConverter(arg).to_java() for arg in method['arguments']]
                    args = ", ".join(args_s)
                    append += '\t'
                    if pretty_print:
                        click.secho("\t", nl=False)
                    append += "static " if method['isStatic'] else ""
                    if pretty_print:
                        click.secho("static " if method['isStatic'] else "", fg='blue', nl=False)
                    ret_type = DvmDescConverter(method['retType'])
                    ret_type = ret_type.short_name() if short_name else ret_type.to_java()
                    ret_type = ret_type + " " if not method['isConstructor'] else ""
                    append += ret_type
                    if pretty_print:
                        click.secho(ret_type, fg='blue', nl=False)
                    append += method['name'] + '('
                    if pretty_print:
                        click.secho(method['name'], fg='red', nl=False)
                        click.secho("(", nl=False)
                    append += args + ");\n"
                    if pretty_print:
                        for index in range(len(args_s)):
                            click.secho(args_s[index], fg='green', nl=False)
                            if index is not len(args_s) - 1:
                                click.secho(", ", nl=False)
                        click.secho(");\n", nl=False)
                except:
                    append += "<unknown error>({})\n".format(method)
                    if pretty_print:
                        click.secho("<unknown error>({})".format(method), fg="bright_red", nl=False)
                        click.secho("")
            return append

        constructors = target['constructors']
        instance_methods = target['instanceMethods']
        static_methods = target['staticMethods']

        result += "\t/* constructor methods */\n"
        if pretty_print:
            click.secho("\t/* constructor methods */", fg="bright_black")
        result += handle_methods(constructors)
        result += "\n"
        if pretty_print: click.secho("")

        result += "\t/* static methods */\n"
        if pretty_print:
            click.secho("\t/* static methods */", fg="bright_black")
        for name in static_methods:
            result += handle_methods(static_methods[name])
        result += "\n"
        if pretty_print: click.secho("")

        result += "\t/* instance methods */\n"
        if pretty_print:
            click.secho("\t/* instance methods */", fg="bright_black")
        for name in instance_methods:
            result += handle_methods(instance_methods[name])
        result += "\n}\n"
        if pretty_print: click.secho("\n}\n", fg='red', nl=False)
        return result

    def _object_dump(self, handle, as_class=None, **kwargs):
        handle = str(handle)
        if as_class is None and handle in self.object_classes:
            return self._object_dump_from_objection_heap(handle, self.object_classes[handle], **kwargs)

        special_render = {
            "java.util.Map": self._map_dump,
            "java.util.Collection": self._collection_dump
        }
        if as_class is None: as_class = self._object_get_classname(handle)
        result = self._class_dump(as_class, handle=handle, **kwargs)
        for clazz in special_render:
            if not self.api.instance_of(handle, clazz):
                continue
            if "pretty_print" in kwargs and kwargs["pretty_print"]:
                click.secho("\n/* special type dump - {} */".format(clazz), fg="bright_black")
            result += special_render[clazz](handle, **kwargs)
        return result

    def _object_dump_from_objection_heap(self, handle, class_name, pretty_print=False, **kwargs):
        api = state_connection.get_api()
        result = ""
        if pretty_print:
            click.secho("")
            click.secho("[wallbreaker] objectdump via objection heap: handle={}, class={}".format(handle, class_name), fg="bright_black")

        try:
            fields = api.android_heap_print_fields(int(handle))
        except Exception as e:
            fields = []
            if pretty_print:
                click.secho("[wallbreaker] failed to read fields: {}".format(e), fg="red")

        try:
            methods = api.android_heap_print_methods(int(handle))
        except Exception as e:
            methods = []
            if pretty_print:
                click.secho("[wallbreaker] failed to read methods: {}".format(e), fg="red")

        result += "class {} {{\n\n".format(class_name)
        if pretty_print:
            click.secho("class ", fg="blue", nl=False)
            click.secho(class_name, nl=False)
            click.secho(" {\n\n", fg="red", nl=False)

        result += "\t/* instance fields */\n"
        if pretty_print:
            click.secho("\t/* instance fields */", fg="bright_black")
        for field in fields:
            line = "\t{} => {}\n".format(field.get('name'), field.get('value'))
            result += line
            if pretty_print:
                click.secho("\t", nl=False)
                click.secho(str(field.get('name')), fg="red", nl=False)
                click.secho(" => ", nl=False)
                click.secho(str(field.get('value')), fg="bright_cyan")

        result += "\n\t/* methods */\n"
        if pretty_print:
            click.secho("\n\t/* methods */", fg="bright_black")
        for method in methods:
            result += "\t{}\n".format(method)
            if pretty_print:
                click.secho("\t{}".format(method))

        result += "\n}\n"
        if pretty_print:
            click.secho("\n}\n", fg="red", nl=False)
        return result

    def _map_dump(self, handle, pretty_print=False, **kwargs):
        result = "{}'s Map Entries {{".format(handle)
        if pretty_print:
            click.secho("{}'s Map Entries ".format(handle), fg='blue', nl=False)
            click.secho("{", fg='red', nl=False)
        pairs = self.api.map_dump(handle)
        for key in pairs:
            result += "\n\t{} => {}".format(key, pairs[key])
            if pretty_print:
                click.secho("\n\t{}".format(key), fg='blue', nl=False)
                click.secho(" => ", nl=False)
                click.secho(pairs[key], fg='bright_cyan', nl=False)

        result += "\n}\n"
        if pretty_print: click.secho("\n}\n", fg='red', nl=False)
        return result

    def _collection_dump(self, handle, pretty_print=False, **kwargs):
        result = "{}'s Collection Entries {{".format(handle)
        if pretty_print:
            click.secho("{}'s Collection Entries ".format(handle), fg='blue', nl=False)
            click.secho("{", fg='red', nl=False)
        array = self.api.collection_dump(handle)
        for i in range(0, len(array)):
            result += "\n\t{} => {}".format(i, array[i])
            if pretty_print:
                click.secho("\n\t{}".format(i), fg='blue', nl=False)
                click.secho(" => ", nl=False)
                click.secho(array[i], fg='bright_cyan', nl=False)

        result += "\n}\n"
        if pretty_print: click.secho("\n}\n", fg='red', nl=False)
        return result


namespace = 'wallbreaker'
plugin = WallBreaker
