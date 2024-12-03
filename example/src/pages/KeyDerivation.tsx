import { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  Clipboard,
} from 'react-native';
import { keyDerivation } from '@mavbozo/react-native-securecrypto';

export default function KeyDerivation() {
  const [masterKey, setMasterKey] = useState('');
  const [domain, setDomain] = useState('');
  const [context, setContext] = useState('');
  const [derivedKey, setDerivedKey] = useState('');

  const deriveKey = async () => {
    try {
      const dk = await keyDerivation.deriveKey({
        masterKey: masterKey,
        domain: domain,
        context: context,
      });
      setDerivedKey(dk);
    } catch (error) {
      console.error('Key derivation error:', error);
      setDerivedKey('Error deriving key');
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Key Derivation</Text>

        <TextInput
          style={[styles.input, styles.fullWidthInput]}
          placeholder="Enter Master Key"
          value={masterKey}
          onChangeText={setMasterKey}
          secureTextEntry
        />

        <TextInput
          style={[styles.input, styles.fullWidthInput]}
          placeholder="Enter Domain"
          value={domain}
          onChangeText={setDomain}
        />

        <TextInput
          style={[styles.input, styles.fullWidthInput]}
          placeholder="Enter Context"
          value={context}
          onChangeText={setContext}
        />

        <TouchableOpacity style={styles.button} onPress={deriveKey}>
          <Text style={styles.buttonText}>Derive Key</Text>
        </TouchableOpacity>
      </View>

      {derivedKey && (
        <View style={styles.resultContainer}>
          <View style={styles.resultRow}>
            <Text style={styles.resultLabel}>Derived Key:</Text>
            <View style={styles.resultValueContainer}>
              <Text style={styles.resultText}>{derivedKey}</Text>
              <TouchableOpacity
                style={styles.copyButton}
                onPress={() => Clipboard.setString(derivedKey)}
              >
                <Text style={styles.copyButtonText}>Copy</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 30,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 30,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    width: 150,
    marginRight: 10,
    borderRadius: 5,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 12,
    borderRadius: 5,
  },
  buttonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  resultRow: {
    marginBottom: 20,
  },
  resultLabel: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 4,
    color: '#666',
  },
  resultValueContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  resultText: {
    flex: 1,
    fontSize: 14,
    fontFamily: 'monospace',
    color: '#333',
    backgroundColor: '#fff',
    padding: 8,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: '#ddd',
  },
  copyButton: {
    marginLeft: 8,
    backgroundColor: '#007AFF',
    padding: 8,
    borderRadius: 4,
  },
  copyButtonText: {
    color: 'white',
    fontSize: 12,
    fontWeight: 'bold',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  resultContainer: {
    backgroundColor: '#f5f5f5',
    padding: 15,
    borderRadius: 8,
    width: '100%',
  },
  section: {
    width: '100%',
    marginBottom: 30,
    backgroundColor: '#f5f5f5',
    padding: 15,
    borderRadius: 8,
  },
  fullWidthInput: {
    width: '100%',
    marginBottom: 10,
  },
});
