package org.schabi.newpipe.settings;

import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;

import org.schabi.newpipe.R;
import org.schabi.newpipe.util.proxy.ProxyLinkParser;
import org.schabi.newpipe.util.proxy.SingBoxConfigGenerator;
import org.schabi.newpipe.util.proxy.StandardV2RayBean;

public class NetworkSettingsFragment extends BasePreferenceFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        addPreferencesFromResourceRegistry();
        
        Preference importPref = findPreference("import_config_link");
        if (importPref != null) {
            importPref.setOnPreferenceClickListener(preference -> {
                showImportDialog();
                return true;
            });
        }
    }

    private void showImportDialog() {
        final EditText input = new EditText(getContext());
        // Try to paste from clipboard automatically
        try {
            ClipboardManager clipboard = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard.hasPrimaryClip() && clipboard.getPrimaryClip().getItemCount() > 0) {
                 CharSequence text = clipboard.getPrimaryClip().getItemAt(0).getText();
                 if (text != null) input.setText(text);
            }
        } catch (Exception ignored) {}

        new AlertDialog.Builder(requireContext())
            .setTitle(R.string.import_config_link_title)
            .setMessage("Paste link (vmess://, vless://, trojan://)")
            .setView(input)
            .setPositiveButton(R.string.ok, (dialog, which) -> {
                String link = input.getText().toString().trim();
                if (!link.isEmpty()) {
                    importLink(link);
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    private void importLink(String link) {
        try {
            StandardV2RayBean bean = ProxyLinkParser.INSTANCE.parse(link);
            if (bean != null) {
                String configJson = SingBoxConfigGenerator.INSTANCE.generate(bean);
                
                EditTextPreference configPref = findPreference("proxy_config_json");
                if (configPref != null) {
                    // Update and save to SharedPreferences
                    configPref.setText(configJson);
                    
                    // Reload Proxy immediately
                    try {
                        org.schabi.newpipe.util.ProxyManager.getInstance(getContext()).startProxy(configJson);
                        Toast.makeText(getContext(), R.string.import_success, Toast.LENGTH_SHORT).show();
                    } catch (Exception e) {
                        Toast.makeText(getContext(), "Failed to reload proxy: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                }
            } else {
                 Toast.makeText(getContext(), "Unsupported link format", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(getContext(), R.string.import_failed, Toast.LENGTH_SHORT).show();
        }
    }
}
