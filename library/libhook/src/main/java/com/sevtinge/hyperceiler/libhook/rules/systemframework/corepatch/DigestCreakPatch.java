package com.sevtinge.hyperceiler.libhook.rules.systemframework.corepatch;

import static com.sevtinge.hyperceiler.libhook.base.BaseHook.findClassIfExists;
import static com.sevtinge.hyperceiler.libhook.base.BaseHook.hookMethod;
import static com.sevtinge.hyperceiler.libhook.utils.api.DeviceHelper.System.isAndroidVersion;
import static com.sevtinge.hyperceiler.libhook.utils.api.DeviceHelper.System.isMoreAndroidVersion;

import android.content.pm.ApplicationInfo;
import android.content.pm.Signature;

import com.sevtinge.hyperceiler.common.log.XposedLog;
import com.sevtinge.hyperceiler.libhook.base.PackageTarget;

import java.lang.reflect.Constructor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import io.github.lingqiqi5211.ezhooktool.xposed.common.HookParam;
import io.github.lingqiqi5211.ezhooktool.xposed.java.IMethodHook;

public class DigestCreakPatch extends CorePatchHelper {

    private final String TAG = "DigestCreak/UsePreSignPatch";

    public void init(PackageTarget lpparam) {
        // Android 14+
        try {
            findAndHookMethod("com.android.server.pm.InstallPackageHelper", lpparam.getClassLoader(),
                "doesSignatureMatchForPermissions", String.class,
                "com.android.internal.pm.parsing.pkg.ParsedPackage", int.class, new IMethodHook() {
                    @Override
                    public void after(HookParam param) {
                        handlePreviousSignature(param);
                    }
                });
        } catch (Throwable t) {
            XposedLog.e(TAG, "system", "Android 14+ hook failed, crash: " + t);
        }

        // Android 13+
        try {
            Class<?> signingDetails = getSigningDetails(lpparam.getClassLoader());
            // New package has a different signature
            // 处理覆盖安装但签名不一致
            hookAllMethods(signingDetails, "checkCapability", new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    // Don't handle PERMISSION & AUTH
                    // Or applications will have all privileged permissions
                    // https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/content/pm/PackageParser.java;l=5947?q=CertCapabilities
                    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java;l=5867
                    if (CorePatchHelper.isFeatureEnabled(CorePatchHelper.PREF_DIGEST_CREAK, true)) {
                        if ((Integer) param.getArgs()[1] != 4 && (Integer) param.getArgs()[1] != 16) {
                            param.setResult(true);
                        }
                    }
                }
            });

            Class<?> ParsedPackage = getParsedPackage(lpparam.getClassLoader());
            findAndHookMethod("com.android.server.pm.InstallPackageHelper", lpparam.getClassLoader(),
                "doesSignatureMatchForPermissions", String.class,
                ParsedPackage, int.class, new IMethodHook() {
                    @Override
                    public void after(HookParam param) {
                        handlePreviousSignature(param);
                    }
                });
        } catch (Throwable t) {
            XposedLog.e(TAG, "system", "Android 13+ hook failed, crash: " + t);
        }

        // Android 12+
        try {
            if (isAndroidVersion(31) || isAndroidVersion(32)) {
                var pmService = findClassIfExists("com.android.server.pm.PackageManagerService",
                    lpparam.getClassLoader());
                if (pmService != null) {
                    var doesSignatureMatchForPermissions = com.sevtinge.hyperceiler.libhook.base.BaseHook.findMethodExactIfExists(pmService, "doesSignatureMatchForPermissions",
                        String.class, "com.android.server.pm.parsing.pkg.ParsedPackage", int.class);
                    if (doesSignatureMatchForPermissions != null) {
                        hookMethod(doesSignatureMatchForPermissions, new IMethodHook() {
                            @Override
                            public void after(HookParam param) {
                                handlePreviousSignature(param);
                            }
                        });
                    }
                }
            }
        } catch (Throwable t) {
            XposedLog.e(TAG, "system", "Android 12+ hook failed, crash: " + t);
        }

        // Android 11+ 1/2
        try {
            // 当 verifyV1Signature 抛出转换异常时，替换一个签名作为返回值
            // 如果用户已安装 apk，并且其定义了私有权限，则安装时会因签名与模块内硬编码的不一致而被拒绝。尝试从待安装apk中获取签名。如果其中apk的签名和已安装的一致（只动了内容）就没有问题。此策略可能有潜在的安全隐患。
            Class<?> pkc = findClass("sun.security.pkcs.PKCS7", lpparam.getClassLoader());
            Constructor<?> constructor = com.sevtinge.hyperceiler.libhook.base.BaseHook.findConstructorExact(pkc, byte[].class);
            constructor.setAccessible(true);
            Class<?> sJarClass = findClass("android.util.jar.StrictJarFile", lpparam.getClassLoader());
            Constructor<?> constructorExact = com.sevtinge.hyperceiler.libhook.base.BaseHook.findConstructorExact(sJarClass, String.class, boolean.class, boolean.class);
            constructorExact.setAccessible(true);
            Class<?> signingDetails = getSigningDetails(lpparam.getClassLoader());
            Constructor<?> findConstructorExact = com.sevtinge.hyperceiler.libhook.base.BaseHook.findConstructorExact(signingDetails, Signature[].class, Integer.TYPE);
            findConstructorExact.setAccessible(true);
            Object[] signingDetailsArgs = new Object[2];
            signingDetailsArgs[1] = 1;
            hookAllMethods("android.util.jar.StrictJarVerifier", lpparam.getClassLoader(), "verifyBytes", new IMethodHook() {
                public void after(HookParam param) {
                    try {
                        if (CorePatchHelper.isFeatureEnabled(CorePatchHelper.PREF_DIGEST_CREAK, true)) {
                            if (!CorePatchHelper.isUsePreSignatureEnabled()) {
                                final Object block = constructor.newInstance(param.getArgs()[0]);
                                Object[] infos = (Object[]) com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(block, "getSignerInfos");
                                Object info = infos[0];
                                @SuppressWarnings("unchecked")
                                List<X509Certificate> verifiedSignerCertChain = (List<X509Certificate>) com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(info, "getCertificateChain", block);
                                if (verifiedSignerCertChain == null) return;
                                param.setResult(verifiedSignerCertChain.toArray(
                                    new X509Certificate[0]));
                            }
                        }
                    } catch (ReflectiveOperationException e) {
                        throw new IllegalStateException(e);
                    }
                }
            });
            // if app is system app, allow to use hidden api, even if app not using a system signature
            findAndHookMethod("android.content.pm.ApplicationInfo", lpparam.getClassLoader(), "isPackageWhitelistedForHiddenApis", new IMethodHook() {
                @Override
                public void before(HookParam param) {
                    if (CorePatchHelper.isFeatureEnabled(CorePatchHelper.PREF_DIGEST_CREAK, true)) {
                        ApplicationInfo info = (ApplicationInfo) param.getThisObject();
                        if ((info.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                            || (info.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                            param.setResult(true);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedLog.e(TAG, "system", "Android 11+ 1/2 hook failed, crash: " + t);
        }

        // Android 11+ 2/2
        try {
            var keySetManagerClass = findClass("com.android.server.pm.KeySetManagerService", lpparam.getClassLoader());
            if (keySetManagerClass != null) {
                var shouldBypass = new ThreadLocal<Boolean>();
                hookAllMethods(keySetManagerClass, "shouldCheckUpgradeKeySetLocked", new IMethodHook() {
                    @Override
                    public void after(HookParam param) {
                        // 检查权限定义的签名的时候，如果定义包名相同，会使用 KeySetManagerService
                        // 我们利用这一点让它通过检查，也就是同包不同签名权限可覆盖
                        // R-Sv2: PackageManagerService#preparePackageLI
                        // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r21:frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java;l=17188;drc=960ffca13a519b0fb9e0942665577c62f97d0eea
                        // T-V: InstallPackageHelper#preparePackageLI
                        // https://cs.android.com/android/platform/superproject/+/android-14.0.0_r2:frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java;l=1097;drc=5ea7e53c3a787e25af86b0f31933ddd68ae3514e
                        // 16: InstallPackageHelper#preparePackage
                        // https://cs.android.com/android/platform/superproject/+/android-16.0.0_r2:frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java;l=1459;drc=d14620262929e39a409b55d11cb542c1d1c4d2f6
                        if (CorePatchHelper.isFeatureEnabled(CorePatchHelper.PREF_DIGEST_CREAK, true) && Arrays.stream(Thread.currentThread().getStackTrace()).anyMatch((o) -> o.getMethodName().startsWith("preparePackage"))) {
                            shouldBypass.set(true);
                            param.setResult(true);
                        } else {
                            shouldBypass.set(false);
                        }
                    }
                });
                hookAllMethods(keySetManagerClass, "checkUpgradeKeySetLocked", new IMethodHook() {
                    @Override
                    public void after(HookParam param) {
                        if (CorePatchHelper.isFeatureEnabled(CorePatchHelper.PREF_DIGEST_CREAK, true) && shouldBypass.get()) {
                            param.setResult(true);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XposedLog.e(TAG, "system", "Android 11+ 2/2 hook failed, crash: " + t);
        }
    }

    /** 防止递归进入 doesSignatureMatchForPermissions（内部复检会再次触发本钩子） */
    private final ThreadLocal<Boolean> mCheckingInstalledSignature = ThreadLocal.withInitial(() -> false);

    /**
     * 旧签名特例（对齐 corepatch upstream 299b265）：
     * 同包名直接放行；否则取已安装包与待安装包做原检查，
     * 放行“只改内容、签名一致”的更新，同时避免同名仿冒。
     */
    private void handlePreviousSignature(HookParam param) {
        if (!CorePatchHelper.isUsePreSignatureEnabled()) return;
        if (!Boolean.FALSE.equals(param.getResult())) return;
        if (Boolean.TRUE.equals(mCheckingInstalledSignature.get())) return;
        Object parsedPackage = param.getArgs()[1];
        if (parsedPackage == null) return;
        Object sourcePackageName = param.getArgs()[0];
        if (sourcePackageName == null) return;
        Object parsedName = com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(parsedPackage, "getPackageName");
        if (sourcePackageName.equals(parsedName)) {
            param.setResult(true);
            return;
        }
        Object helper = param.getThisObject();
        if (helper == null) return;
        Object oldPackage = findInstalledPackage(helper, String.valueOf(parsedName));
        if (oldPackage == null) return;
        mCheckingInstalledSignature.set(true);
        try {
            Object matches = com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(
                helper, "doesSignatureMatchForPermissions", sourcePackageName, oldPackage, param.getArgs()[2]);
            if (Boolean.TRUE.equals(matches)) param.setResult(true);
        } catch (Throwable t) {
            XposedLog.w(TAG, "system", "failed to check the installed package signature", t);
        } finally {
            mCheckingInstalledSignature.remove();
        }
    }

    /** mPm → snapshotComputer() → getPackageStateInternal(name) → getAndroidPackage() */
    private Object findInstalledPackage(Object helper, String packageName) {
        try {
            Object pm = com.sevtinge.hyperceiler.libhook.base.BaseHook.getObjectField(helper, "mPm");
            Object computer = com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(pm, "snapshotComputer");
            Object state = com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(computer, "getPackageStateInternal", packageName);
            if (state == null) return null;
            return com.sevtinge.hyperceiler.libhook.base.BaseHook.callMethod(state, "getAndroidPackage");
        } catch (Throwable t) {
            XposedLog.w(TAG, "system", "failed to find the installed package", t);
            return null;
        }
    }

    Class<?> getParsedPackage(ClassLoader classLoader) {
        if (isMoreAndroidVersion(35)) {
            return findClassIfExists("com.android.internal.pm.parsing.pkg.ParsedPackage", classLoader);
        } else if (isMoreAndroidVersion(34)) {
            var clazz = findClassIfExists("com.android.internal.pm.parsing.pkg.ParsedPackage", classLoader);
            return clazz != null ? clazz : findClassIfExists("com.android.server.pm.parsing.pkg.ParsedPackage", classLoader);
        }
        return findClassIfExists("com.android.server.pm.parsing.pkg.ParsedPackage", classLoader);
    }

    Class<?> getSigningDetails(ClassLoader classLoader) {
        if (isMoreAndroidVersion(33)) {
            return findClassIfExists("android.content.pm.SigningDetails", classLoader);
        }
        return findClass("android.content.pm.PackageParser.SigningDetails", classLoader);
    }
}
