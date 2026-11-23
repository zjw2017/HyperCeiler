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

/**
 * 跳过安装时的开发者验证（Android 16 QPR2+）。
 * <p>
 * 对齐 corepatch upstream（4db4801）：PackageInstallerSession
 * .shouldUseVerificationService() 恒返回 false；同时反优化
 * startDeveloperVerificationSession，保证被内联的检查也能进入钩子。
 */
public class DisableDeveloperVerification extends BaseHook {

    private static final String TAG = "DisableDeveloperVerification";

    @Override
    public void init() {
        // https://android.googlesource.com/platform/frameworks/base/+/android16-qpr2-release/services/core/java/com/android/server/pm/PackageInstallerSession.java#3051
        Class<?> sessionClass = findClassIfExists("com.android.server.pm.PackageInstallerSession");
        if (sessionClass == null) return;
        Method target = null;
        for (Method method : sessionClass.getDeclaredMethods()) {
            if ("shouldUseVerificationService".equals(method.getName())
                && method.getParameterCount() == 0
                && method.getReturnType() == Boolean.TYPE) {
                target = method;
                break;
            }
        }
        if (target == null) {
            XposedLog.w(TAG, "system", "shouldUseVerificationService not found (older Android?)");
            return;
        }
        // 反优化调用方，保证内联的检查仍会进入钩子
        deoptimizeMethods(sessionClass, "startDeveloperVerificationSession");
        hookMethod(target, returnConstant(false));
        XposedLog.i(TAG, "system", "hooked PackageInstallerSession#shouldUseVerificationService");
    }
}
