__description__ = "a plugin to help you understand java world."

import json
import os

import click

from objection.utils.plugin import Plugin


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

        self.inject()

    def classdump(self, args=None):
        short_name = True
        target_name = ""
        for arg in args:
            if arg == "--fullname":
                short_name = False
            else:
                target_name = arg

        self._class_dump(target_name, pretty_print=True, short_name=short_name)

    def classsearch(self, args=None):
        pattern = args[0]
        instances = self.api.class_match(pattern)
        print("\n".join(instances))

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
        instances = self.api.object_search(clsname, stop=False)
        for handle in instances:
            print("[{}]: {}".format(handle, instances[handle]))

    def _class_match(self, pattern):
        return self.api.class_match(pattern)

    def _class_use(self, name):
        return json.loads(self.api.class_use(name))

    def _object_get_classname(self, handle):
        return self.api.object_get_class(handle)

    def _object_get_field(self, handle, field, as_class=None):
        return self.api.object_get_field(handle, field, as_class)

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
        special_render = {
            "java.util.Map": self._map_dump,
            "java.util.Collection": self._collection_dump
        }
        handle = str(handle)
        if as_class is None: as_class = self._object_get_classname(handle)
        result = self._class_dump(as_class, handle=handle, **kwargs)
        for clazz in special_render:
            if not self.api.instance_of(handle, clazz):
                continue
            if "pretty_print" in kwargs and kwargs["pretty_print"]:
                click.secho("\n/* special type dump - {} */".format(clazz), fg="bright_black")
            result += special_render[clazz](handle, **kwargs)
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
