import { useState } from 'react';
import {
  Text,
  View,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import RSA, { getKeyInfo, base64ToUtf8 } from '@avieldr/react-native-rsa';

type LogEntry = { label: string; value: string };

export default function App() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);

  const addLog = (label: string, value: string) => {
    setLogs((prev) => [...prev, { label, value }]);
  };

  const clearLogs = () => setLogs([]);

  // --- Key Generation Tests ---

  const runGenerateKeyPair = async (
    keySize: number,
    format: 'pkcs1' | 'pkcs8' = 'pkcs1'
  ) => {
    setLoading(true);
    clearLogs();
    addLog('Action', `generateKeyPair(${keySize}, ${format})`);
    try {
      const start = Date.now();
      const result = await RSA.generateKeyPair(keySize, { format });
      const elapsed = Date.now() - start;

      addLog('Time', `${elapsed}ms`);
      addLog('Private Key', result.privateKey.substring(0, 80) + '...');
      addLog('Public Key', result.publicKey.substring(0, 80) + '...');

      const privInfo = getKeyInfo(result.privateKey);
      addLog('Private Key Format', privInfo.format);
      addLog('Private Key Valid', String(privInfo.isValid));
      addLog('Private Key DER bytes', String(privInfo.derByteLength));

      const pubInfo = getKeyInfo(result.publicKey);
      addLog('Public Key Format', pubInfo.format);
      addLog('Public Key Valid', String(pubInfo.isValid));
    } catch (e: any) {
      addLog('Error', e.message ?? String(e));
    }
    setLoading(false);
  };

  const runExtractPublicKey = async () => {
    setLoading(true);
    clearLogs();
    addLog('Action', 'getPublicKeyFromPrivate');
    try {
      const { privateKey } = await RSA.generateKeyPair(2048);
      addLog('Generated private key', privateKey.substring(0, 60) + '...');

      const start = Date.now();
      const publicKey = await RSA.getPublicKeyFromPrivate(privateKey);
      const elapsed = Date.now() - start;

      addLog('Time', `${elapsed}ms`);
      addLog('Public Key', publicKey.substring(0, 80) + '...');

      const info = getKeyInfo(publicKey);
      addLog('Format', info.format);
      addLog('Valid', String(info.isValid));
    } catch (e: any) {
      addLog('Error', e.message ?? String(e));
    }
    setLoading(false);
  };

  // --- Encrypt / Decrypt Tests ---

  const runEncryptDecrypt = async () => {
    setLoading(true);
    clearLogs();
    addLog('Action', 'Encrypt / Decrypt round-trip (OAEP + SHA-256)');
    try {
      // Generate a fresh key pair for testing
      const { publicKey, privateKey } = await RSA.generateKeyPair(2048);
      addLog('Key pair', '2048-bit PKCS#1 generated');

      const plaintext = 'Hello RSA!';
      addLog('Plaintext', plaintext);

      const start = Date.now();

      // Encrypt with public key (defaults: OAEP + SHA-256 + UTF-8 encoding)
      const encrypted = await RSA.encrypt(plaintext, publicKey);
      addLog('Encrypted (base64)', encrypted.substring(0, 60) + '...');

      // Decrypt with private key — returns base64-encoded plaintext
      const decryptedBase64 = await RSA.decrypt(encrypted, privateKey);

      // Decode base64 back to UTF-8 text
      const decrypted = base64ToUtf8(decryptedBase64);
      const elapsed = Date.now() - start;

      addLog('Decrypted', decrypted);
      addLog('Round-trip match', String(decrypted === plaintext));
      addLog('Time', `${elapsed}ms`);
    } catch (e: any) {
      addLog('Error', e.message ?? String(e));
    }
    setLoading(false);
  };

  // --- Sign / Verify Tests ---

  const runSignVerify = async () => {
    setLoading(true);
    clearLogs();
    addLog('Action', 'Sign / Verify round-trip (PSS + SHA-256)');
    try {
      // Generate a fresh key pair for testing
      const { publicKey, privateKey } = await RSA.generateKeyPair(2048);
      addLog('Key pair', '2048-bit PKCS#1 generated');

      const message = 'Hello RSA!';
      addLog('Message', message);

      const start = Date.now();

      // Sign with private key (defaults: PSS + SHA-256 + UTF-8 encoding)
      const signature = await RSA.sign(message, privateKey);
      addLog('Signature (base64)', signature.substring(0, 60) + '...');

      // Verify with correct data — should be true
      const valid = await RSA.verify(message, signature, publicKey);
      addLog('Verify (correct data)', String(valid));

      // Verify with wrong data — should be false
      const invalid = await RSA.verify('Wrong data', signature, publicKey);
      addLog('Verify (wrong data)', String(invalid));

      const elapsed = Date.now() - start;
      addLog('Time', `${elapsed}ms`);
    } catch (e: any) {
      addLog('Error', e.message ?? String(e));
    }
    setLoading(false);
  };

  // --- Convert Key Tests ---

  const runConvertKey = async () => {
    setLoading(true);
    clearLogs();
    addLog('Action', 'Convert private key PKCS#1 → PKCS#8 → PKCS#1');
    try {
      // Start with a PKCS#1 key
      const { privateKey } = await RSA.generateKeyPair(2048, {
        format: 'pkcs1',
      });
      addLog('Original (PKCS#1)', privateKey.substring(0, 60) + '...');

      const start = Date.now();

      // Convert PKCS#1 → PKCS#8
      const pkcs8 = await RSA.convertPrivateKey(privateKey, 'pkcs8');
      addLog('Converted (PKCS#8)', pkcs8.substring(0, 60) + '...');

      const pkcs8Info = getKeyInfo(pkcs8);
      addLog('PKCS#8 format', pkcs8Info.format);
      addLog('PKCS#8 valid', String(pkcs8Info.isValid));

      // Convert back PKCS#8 → PKCS#1
      const backToPkcs1 = await RSA.convertPrivateKey(pkcs8, 'pkcs1');
      addLog('Back to PKCS#1', backToPkcs1.substring(0, 60) + '...');

      const pkcs1Info = getKeyInfo(backToPkcs1);
      addLog('PKCS#1 format', pkcs1Info.format);
      addLog('PKCS#1 valid', String(pkcs1Info.isValid));

      const elapsed = Date.now() - start;
      addLog('Time', `${elapsed}ms`);
    } catch (e: any) {
      addLog('Error', e.message ?? String(e));
    }
    setLoading(false);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>@avieldr/react-native-rsa</Text>

      {/* Row 1: Key generation buttons */}
      <ScrollView
        horizontal
        style={styles.buttonRow}
        contentContainerStyle={styles.buttonRowContent}
      >
        <TouchableOpacity
          style={styles.btn}
          onPress={() => runGenerateKeyPair(1024)}
        >
          <Text style={styles.btnText}>1024 PKCS#1</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.btn}
          onPress={() => runGenerateKeyPair(2048)}
        >
          <Text style={styles.btnText}>2048 PKCS#1</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.btn}
          onPress={() => runGenerateKeyPair(4096)}
        >
          <Text style={styles.btnText}>4096 PKCS#1</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.btn}
          onPress={() => runGenerateKeyPair(2048, 'pkcs8')}
        >
          <Text style={styles.btnText}>2048 PKCS#8</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.btn} onPress={runExtractPublicKey}>
          <Text style={styles.btnText}>Extract PubKey</Text>
        </TouchableOpacity>
      </ScrollView>

      {/* Row 2: Crypto operation buttons */}
      <ScrollView
        horizontal
        style={styles.buttonRow}
        contentContainerStyle={styles.buttonRowContent}
      >
        <TouchableOpacity
          style={[styles.btn, styles.btnGreen]}
          onPress={runEncryptDecrypt}
        >
          <Text style={styles.btnText}>Encrypt/Decrypt</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.btn, styles.btnGreen]}
          onPress={runSignVerify}
        >
          <Text style={styles.btnText}>Sign/Verify</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.btn, styles.btnOrange]}
          onPress={runConvertKey}
        >
          <Text style={styles.btnText}>Convert Key</Text>
        </TouchableOpacity>
      </ScrollView>

      {loading && <ActivityIndicator size="small" style={styles.spinner} />}

      <ScrollView style={styles.logContainer}>
        {logs.map((entry, i) => (
          <View key={i} style={styles.logRow}>
            <Text style={styles.logLabel}>{entry.label}:</Text>
            <Text style={styles.logValue} selectable>
              {entry.value}
            </Text>
          </View>
        ))}
        {logs.length === 0 && (
          <Text style={styles.placeholder}>Tap a button above to test</Text>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, paddingTop: 60, backgroundColor: '#f5f5f5' },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 16,
  },
  buttonRow: { maxHeight: 50, marginBottom: 8 },
  buttonRowContent: { paddingHorizontal: 12, gap: 8 },
  btn: {
    backgroundColor: '#007AFF',
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 8,
  },
  btnGreen: { backgroundColor: '#34C759' },
  btnOrange: { backgroundColor: '#FF9500' },
  btnText: { color: '#fff', fontWeight: '600', fontSize: 13 },
  spinner: { marginVertical: 8 },
  logContainer: { flex: 1, paddingHorizontal: 16, marginTop: 8 },
  logRow: { flexDirection: 'row', marginBottom: 6 },
  logLabel: { fontWeight: '600', marginRight: 6, fontSize: 13, color: '#333' },
  logValue: { flex: 1, fontSize: 13, color: '#555' },
  placeholder: { textAlign: 'center', color: '#999', marginTop: 40 },
});
