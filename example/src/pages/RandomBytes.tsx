import { useState } from 'react';
import {
  StyleSheet,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Clipboard,
} from 'react-native';
import { random } from 'react-native-securecrypto';

export default function RandomBytes() {
  const [results, setResults] = useState({
    bytes: '',
    hex: '',
    base64: '',
  });
  const [numBytes, setNumBytes] = useState<string>('10');

  const handleGenerate = async () => {
    try {
      const bytesArray = await random.generateRandomBytes(Number(numBytes));
      const bytes = Array.from(bytesArray).join(',');
      const hex = await random.generateRandomBytesAsHex(Number(numBytes));
      const base64 = await random.generateRandomBytesAsBase64(Number(numBytes));
      setResults({ bytes, hex, base64 });
    } catch (error) {
      console.error('Error generating random bytes:', error);
    }
  };

  const handleCopy = async (text: string) => {
    await Clipboard.setString(text);
  };

  const ResultRow = ({ label, value }: { label: string; value: string }) => (
    <View style={styles.resultRow}>
      <Text style={styles.resultLabel}>{label}:</Text>
      <View style={styles.resultValueContainer}>
        <Text selectable style={styles.resultText}>
          {value}
        </Text>
        <TouchableOpacity
          style={styles.copyButton}
          onPress={() => handleCopy(value)}
        >
          <Text style={styles.copyButtonText}>Copy</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Random Bytes Generator</Text>

      <View style={styles.section}>
        <View style={styles.inputContainer}>
          <TextInput
            style={styles.input}
            value={numBytes}
            onChangeText={setNumBytes}
            keyboardType="numeric"
            placeholder="Enter number of bytes"
          />
          <TouchableOpacity style={styles.button} onPress={handleGenerate}>
            <Text style={styles.buttonText}>Generate</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.resultContainer}>
          <Text style={styles.sectionTitle}>
            Three Different Random Values:
          </Text>
          <ResultRow label="Random Value 1 (as Bytes)" value={results.bytes} />
          <ResultRow label="Random Value 2 (as Hex)" value={results.hex} />
          <ResultRow
            label="Random Value 3 (as Base64)"
            value={results.base64}
          />
        </View>
      </View>
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
