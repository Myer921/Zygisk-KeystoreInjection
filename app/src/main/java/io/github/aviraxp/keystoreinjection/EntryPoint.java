package io.github.aviraxp.keystoreinjection;

import android.util.Log;
import android.text.TextUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.json.JSONException;
import org.json.JSONObject;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.Iterator;

public final class EntryPoint {
    private static final Map<String, Keybox> certs = new HashMap<>();
    private static final Map<String, Certificate> store = new HashMap<>();
    private static final Map<Field, String> map = new HashMap<>();
    public static final String TAG = "KeystoreInjection";

    static {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            Field keyStoreSpi = keyStore.getClass().getDeclaredField("keyStoreSpi");

            keyStoreSpi.setAccessible(true);

            CustomKeyStoreSpi.keyStoreSpi = (KeyStoreSpi) keyStoreSpi.get(keyStore);

        } catch (Throwable t) {
            Log.e(TAG, "Couldn't get keyStoreSpi field!", t);
        }

        Provider provider = Security.getProvider("AndroidKeyStore");

        Provider customProvider = new CustomProvider(provider);

        Security.removeProvider("AndroidKeyStore");
        Security.insertProviderAt(customProvider, 1);
    }

    public static void receiveXml(String data) {
        XMLParser xmlParser = new XMLParser(data);

        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                    "AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();
                LinkedList<X500Name> certificateChainHolders = new LinkedList<>();

                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String, String> certData = xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(CertUtils.parseCert(certData.get("text")));
                    certificateChainHolders.add(CertUtils.parseCertSubject(certData.get("text")));
                }
                certs.put(keyboxAlgorithm, new Keybox(CertUtils.parseKeyPair(privateKey),
                        CertUtils.parsePrivateKey(privateKey), certificateChain, certificateChainHolders));
            }
        } catch (Throwable t) {
            Log.e(TAG, Log.getStackTraceString(t));
        }
    }

    public static void receiveJson(String json) {
        boolean spoofPackageManager = false;

        JSONObject jsonObject = null;

        try {
            jsonObject = new JSONObject(json);
        } catch (JSONException e) {
            Log.e(TAG, "Can't parse json", e);
        }

        if (jsonObject == null || jsonObject.length() == 0) return;

        Iterator<String> it = jsonObject.keys();

        while (it.hasNext()) {
            String key = it.next();

            String value = "";
            try {
                value = jsonObject.getString(key);
            } catch (JSONException e) {
                Log.e(TAG, "Couldn't get value from key", e);
            }

            if (TextUtils.isEmpty(value)) continue;

            if ("SPOOF_PACKAGE_MANAGER".equals(key) && Boolean.parseBoolean(value)) {
                spoofPackageManager = true;
                continue;
            }

            Field field = getFieldByName(key);

            if (field == null) continue;

            map.put(field, value);
        }

        Log.i(TAG, "Fields ready to spoof: " + map.size());

        spoofFields();
        if (spoofPackageManager) spoofPackageManager();
    }

    private static void spoofFields() {
        map.forEach((field, s) -> {
            try {
                if (s.equals(field.get(null))) return;
                field.setAccessible(true);
                String oldValue = String.valueOf(field.get(null));
                field.set(null, s);
                Log.d(TAG, String.format("""
                        ---------------------------------------
                        [%s]
                        OLD: '%s'
                        NEW: '%s'
                        ---------------------------------------
                        """, field.getName(), oldValue, field.get(null)));
            } catch (Throwable t) {
                Log.e(TAG, "Error modifying field", t);
            }
        });
    }

    private static Field getFieldByName(String name) {
        Field field;
        try {
            field = Build.class.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            try {
                field = Build.VERSION.class.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                return null;
            }
        }
        field.setAccessible(true);
        return field;
    }

    private static void spoofPackageManager() {
        // 实现伪造 PackageManager 的代码
    }

    static void append(String a, Certificate c) {
        store.put(a, c);
    }

    static Certificate retrieve(String a) {
        return store.get(a);
    }

    static Keybox box(String type) {
        return certs.get(type);
    }
}
