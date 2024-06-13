package com.sevtinge.hyperceiler.ui.settings.core.lifecycle;

import android.content.SharedPreferences;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.lifecycle.Lifecycle;

import com.sevtinge.hyperceiler.utils.prefs.PrefsUtils;

import fan.preference.PreferenceFragment;

public abstract class ObservablePreferenceFragment extends PreferenceFragment {

    private Lifecycle mLifecycle = null;

    @Override
    public void onCreatePreferences(@Nullable Bundle bundle, @Nullable String s) {
        PrefsUtils.setSharedPreferences(getPreferenceManager());
    }

    public SharedPreferences getSharedPreferences() {
        return PrefsUtils.mSharedPreferences;
    }

    public boolean hasKey(String key) {
        return getSharedPreferences().contains(key);
    }
}
