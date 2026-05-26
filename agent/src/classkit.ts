/*
* Author: hluwa <hluwa888@gmail.com>
* HomePage: https://github.com/hluwa
* CreateTime: 2019/12/4
* */

import {ClassWrapper} from "./struct";

const debug = (event: string, detail: any = {}) => {
    try {
        send({
            type: "wallbreaker-debug",
            event: event,
            detail: detail
        });
    } catch (e) {
    }
};

const errorMessage = (e: any) => {
    if (e && e.stack) {
        return e.stack;
    }
    return String(e);
};

const isJavaAvailable = () => {
    try {
        return Java.available;
    } catch (e) {
        return false;
    }
};

export const match = (name: string) => {
    let result: Array<string> = [];
    try {
        if (!isJavaAvailable()) {
            debug("java_unavailable", {
                operation: "class_match",
                pattern: name,
                message: "Frida Java bridge is unavailable in the current process. Check that Objection is attached to the Android app process after ART is initialized."
            });
            return result;
        }

        Java.performNow(function () {
            debug("class_match_start", {pattern: name});
            Java.enumerateLoadedClassesSync().forEach(function (p1: string) {
                if (p1.startsWith("[")) {
                    return
                }
                if (p1.match(name)) {
                    result.push(p1)
                }
            });
            debug("class_match_done", {pattern: name, count: result.length});
        });
    } catch (e) {
        debug("class_match_error", {pattern: name, error: errorMessage(e)});
    }
    return result;
};

export const use = (name: string) => {
    let result = ClassWrapper.NONE;
    try {
        if (!isJavaAvailable()) {
            debug("java_unavailable", {
                operation: "class_use",
                name: name,
                message: "Frida Java bridge is unavailable in the current process. Check that Objection is attached to the Android app process after ART is initialized."
            });
            return result;
        }

        Java.performNow(function () {
            debug("class_use_start", {name: name});
            result = ClassWrapper.byWrapper(Java.use(name));
            debug("class_use_done", {
                name: name,
                constructors: result.constructors.length,
                staticMethods: Object.keys(result.staticMethods).length,
                instanceMethods: Object.keys(result.instanceMethods).length,
                staticFields: Object.keys(result.staticFields).length,
                instanceFields: Object.keys(result.instanceFields).length
            });
        });
    } catch (e) {
        debug("class_use_error", {name: name, error: errorMessage(e)});
    }
    return result;
};
