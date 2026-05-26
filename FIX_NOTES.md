# Wallbreaker / Objection Frida 17 Compatibility Notes

## Environment

- Device: Android 13
- Frida client/server: 17.9.11
- Objection fork: `<objection-fork>`
- Wallbreaker plugin path: `<wallbreaker-plugin-path>`

## Symptoms

Initial Wallbreaker commands returned empty results or `NONE`:

```text
plugin wallbreaker classsearch <class>
[wallbreaker-agent] java_unavailable ...
```

Objection built-in Android commands also failed:

```text
android hooking list classes
Error: Unable to find copied methods in java/lang/Thread; please file a bug
```

Pure Frida worked:

```js
Java.perform(function () {
  console.log(Java.enumerateLoadedClassesSync().length);
});
```

This proved Frida and the target app were usable; the issue was in Objection/Wallbreaker integration.

## Root Causes

### 1. Objection bundled bridge compatibility

The Objection fork bundled `frida-java-bridge@7.0.10`. On this Android 13 target it failed while resolving ART internals:

```text
Unable to find copied methods in java/lang/Thread
```

Upgrading to `frida-java-bridge@7.0.13` fixed the class/method enumeration path.

### 2. Frida 17 Java global behavior

In this environment:

```js
typeof Java              // "object" in some Objection evaluate contexts
typeof globalThis.Java   // "undefined"
```

The Objection fork checked only `globalThis.Java`, so it incorrectly fell back to bundled `frida-java-bridge`.

### 3. Wallbreaker private agent cannot see Java

Wallbreaker injects a separate Frida script. Under Frida 17, that plugin script reported:

```text
agent_loaded {"javaType": "undefined", "javaAvailable": false}
```

So commands depending on Wallbreaker private JS agent failed:

- `classdump`
- `objectdump` without Objection heap cache
- map/collection special dump

### 4. Frida 17 Python RPC keyword arguments

Wallbreaker called:

```python
self.api.object_search(clsname, stop=False)
```

Frida 17 Python RPC rejects keyword arguments:

```text
Script._rpc_request() got an unexpected keyword argument 'stop'
```

Use positional arguments instead.

## Changes Made

### Objection fork

Location:

```text
<tmp-objection-fork>
```

Changed:

- `agent/package.json`
- `agent/package-lock.json`
- `agent/src/android/lib/libjava.ts`
- `objection/utils/agent.py`

Main changes:

1. Upgraded bundled Java bridge:

```text
frida-java-bridge 7.0.10 -> 7.0.13
```

2. Reworked `libjava.ts` to avoid relying on `globalThis.Java`.

3. Changed `getApplicationContext()` to use the selected bridge:

```ts
const ActivityThread = getJavaBridge().use("android.app.ActivityThread");
```

4. Added spawn/resume/re-attach probing in `objection/utils/agent.py`.

Observation: the probe may still report `Java` unavailable before loading agent, but the bundled bridge path now works for tested commands.

Build command:

```bash
cd <tmp-objection-fork>/agent
npm run build
```

Run patched Objection:

```bash
source <venv-path>/bin/activate
objection -d -n <target-app-package> -s -p start -P <plugins-path>
```

### Wallbreaker

Changed:

- `__init__.py`
- `agent/src/classkit.ts`
- `agent/src/index.ts`
- `agent/src/objectkit.ts`
- `agent/_agent.js`
- `wallbreaker/agent/command/agent.js`

Important behavioral changes:

1. `classsearch` now prefers Objection API:

```python
state_connection.get_api().android_hooking_enumerate(pattern)
```

2. `objectsearch` now prefers Objection heap API:

```python
state_connection.get_api().android_heap_get_live_class_instances(clsname)
```

3. `objectsearch` caches:

```text
hashcode -> class name
```

4. `objectdump <hashcode>` uses the cache and Objection heap APIs:

```python
android_heap_print_fields(handle)
android_heap_print_methods(handle)
```

5. Wallbreaker private agent injection is lazy and used only as fallback.

## Working Commands

Validated:

```text
android hooking search MainActivity --only-classes
android hooking list activities
plugin wallbreaker classsearch <target-app-package>.page.MainActivity
plugin wallbreaker objectsearch <target-app-package>.page.MainActivity
plugin wallbreaker objectdump <hashcode-from-objectsearch>
```

Example:

```text
plugin wallbreaker objectsearch <class>
[115262253]: <instance-string>

plugin wallbreaker objectdump 115262253
```

## Known Limitations

- `plugin wallbreaker classdump <class>` still depends on Wallbreaker private agent and may return `NONE`.
- `objectdump` only uses Objection heap path if the hashcode was discovered by `objectsearch` in the same session.
- `objectdump --as-class ...` may still hit the old Wallbreaker agent path.
- Map/Collection special rendering still depends on Wallbreaker private agent:

```python
self.api.map_dump(handle)
self.api.collection_dump(handle)
```

These may fail with `Java is not defined`.

## Recommended Direction

Do not add another bundled `frida-java-bridge` to Wallbreaker unless absolutely necessary.

Better path:

1. Treat Wallbreaker as a Python command/formatting layer.
2. Prefer Objection's fixed RPC APIs for Java work.
3. Migrate `classdump` to Objection APIs:
   - `android_hooking_get_class_methods`
   - optional new Objection RPC for fields/constructors/static fields
4. Migrate map/collection dump into Objection agent if needed.
5. Keep Wallbreaker private JS agent only as legacy fallback.

## Quick Troubleshooting

Check active Objection:

```bash
which objection
python -c "import objection; print(objection.__file__)"
```

Expected patched source:

```text
<venv-path>/bin/objection
<tmp-objection-fork>/objection/__init__.py
```

Check Frida:

```bash
python -c "import frida; print(frida.__version__)"
frida --version
```

Check Java in plain Frida:

```bash
frida -U -f <package> -e '
setImmediate(function () {
  Java.perform(function () {
    console.log(Java.enumerateLoadedClassesSync().length);
  });
});
' --no-pause
```

Check Objection Java behavior:

```text
evaluate
```

Paste:

```js
console.log('typeof Java=', typeof Java);
console.log('Java.available=', typeof Java !== 'undefined' && Java.available);
```

If pure Frida works but Objection fails, inspect Objection agent bridge/version first.
