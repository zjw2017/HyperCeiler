/*
 * This file is part of HyperCeiler.

 * HyperCeiler is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.

 * Copyright (C) 2023-2026 HyperCeiler Contributions
 */
package com.sevtinge.hyperceiler.libhook.rules.systemframework.corepatch;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.BaseHook;

import java.lang.reflect.Method;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

/**
 * 绕过 minSdkVersion 校验，允许安装 minSdk 高于当前系统版本的应用。
 * <p>
 * 对齐 corepatch upstream（ddf87bb）：把 computeMinSdkVersion 的 minVers
 * 钳制到平台版本；无 minCode（非预发布）时生效，不写死混淆名。
 */
public class BypassMinSdkCheck extends BaseHook {

    private static final String TAG = "BypassMinSdkCheck";

    @Override
    public void init() {
        // https://cs.android.com/android/platform/superproject/+/android-9.0.0_r61:frameworks/base/core/java/android/content/pm/PackageParser.java;l=2625
        // public static int computeMinSdkVersion(int minVers, String minCode, int platformSdkVersion, String[] platformSdkCodenames, String[] outError)
        // https://cs.android.com/android/platform/superproject/+/android-13.0.0_r1:frameworks/base/core/java/android/content/pm/parsing/FrameworkParsingPackageUtils.java;l=298
        // public static ParseResult<Integer> computeMinSdkVersion(int minVers, String minCode, int platformSdkVersion, String[] platformSdkCodenames, ParseInput input)
        for (String className : new String[]{
            "android.content.pm.PackageParser",
            "android.content.pm.parsing.ParsingPackageUtils",
            "android.content.pm.parsing.FrameworkParsingPackageUtils",
        }) {
            Class<?> clazz = findClassIfExists(className);
            if (clazz == null) continue;
            for (Method method : clazz.getDeclaredMethods()) {
                if (!"computeMinSdkVersion".equals(method.getName())) continue;
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length < 3
                    || parameterTypes[0] != Integer.TYPE
                    || parameterTypes[1] != String.class
                    || parameterTypes[2] != Integer.TYPE) {
                    continue;
                }
                hookMethod(method, new IMethodHook() {
                    @Override
                    public void before(HookParam param) {
                        if (param.getArgs()[1] != null) return;
                        int minVers = (int) param.getArgs()[0];
                        int platformSdkVersion = (int) param.getArgs()[2];
                        if (minVers > platformSdkVersion) {
                            param.getArgs()[0] = platformSdkVersion;
                        }
                    }
                });
                XposedLog.i(TAG, "system", "hooked " + className + "#computeMinSdkVersion");
            }
        }
    }
}
