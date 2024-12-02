import { useState, useEffect } from 'react';
import {
  StyleSheet,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Clipboard,
  ScrollView,
} from 'react-native';
import { cipher, random } from 'react-native-securecrypto';
import { Buffer } from 'buffer';
import RNFS from 'react-native-fs';

type Results = {
  encrypted: string;
  decrypted: string;
  bytesEncrypted: Uint8Array;
  bytesDecrypted: Uint8Array;
};

export default function Encryption() {
  const generateRandomKey = async () => {
    try {
      return await random.generateRandomBytesAsBase64(32);
    } catch (error) {
      console.error('Error generating random key:', error);
      return '';
    }
  };

  const [results, setResults] = useState<Results>({
    encrypted: '',
    decrypted: '',
    bytesEncrypted: new Uint8Array(),
    bytesDecrypted: new Uint8Array(),
  });
  const [inputText, setInputText] = useState<string>('');
  const [inputBytes, setInputBytes] = useState<string>('');
  const [stringEncryptionKey, setStringEncryptionKey] = useState<string>('');
  const [bytesEncryptionKey, setBytesEncryptionKey] = useState<string>('');
  const [fileEncryptionKey, setFileEncryptionKey] = useState<string>('');
  const [fileOperationStatus, setFileOperationStatus] = useState<string>('');
  const [fileInputText, setFileInputText] = useState<string>('');
  const [decryptedFileContent, setDecryptedFileContent] = useState<string>('');

  useEffect(() => {
    const initializeKeys = async () => {
      const randomKey = await generateRandomKey();
      console.log('randomKey', randomKey);
      setStringEncryptionKey(randomKey);
      setBytesEncryptionKey(randomKey);
      setFileEncryptionKey(randomKey);
    };
    initializeKeys();
  }, []);

  const handleStringEncrypt = async () => {
    try {
      const encrypted = await cipher.encryptString(
        {
          algorithm: 'AES-GCM',
          key: stringEncryptionKey,
        },
        inputText
      );

      const decrypted = await cipher.decryptString(
        {
          algorithm: 'AES-GCM',
          key: stringEncryptionKey,
        },
        encrypted
      );
      // debug inputText, encrypted, decrypted
      console.log('inputText', inputText);
      console.log('encrypted', encrypted);
      console.log('decrypted', decrypted);
      setResults((prev) => ({ ...prev, encrypted, decrypted }));
    } catch (error) {
      console.error('Error encrypting/decrypting string:', error);
    }
  };

  const handleBytesEncrypt = async () => {
    try {
      const bytes = new Uint8Array(Buffer.from(inputBytes, 'utf8'));

      const encrypted = await cipher.encryptBytes(
        {
          algorithm: 'AES-GCM',
          key: bytesEncryptionKey,
        },
        bytes
      );

      const decrypted = await cipher.decryptBytes(
        {
          algorithm: 'AES-GCM',
          key: bytesEncryptionKey,
        },
        encrypted
      );

      const decryptedString = Buffer.from(decrypted).toString('utf8');
      console.log('Original text:', inputBytes);
      console.log('Decrypted text:', decryptedString);

      setResults((prev) => ({
        ...prev,
        bytesEncrypted: encrypted,
        bytesDecrypted: decrypted,
      }));
    } catch (error) {
      console.error('Error encrypting/decrypting bytes:', error);
    }
  };

  const handleCopy = async (bytes: Uint8Array) => {
    const base64 = Buffer.from(bytes).toString('base64');
    await Clipboard.setString(base64);
  };

  const handleFileEncrypt = async () => {
    try {
      setFileOperationStatus('Processing...');
      console.log('Starting file encryption process');
      console.log('Input text:', fileInputText);

      // Create temporary files in app's documents directory
      const inputPath = `${RNFS.DocumentDirectoryPath}/input_file.txt`;
      const encryptedPath = `${RNFS.DocumentDirectoryPath}/encrypted_file`;
      const decryptedPath = `${RNFS.DocumentDirectoryPath}/decrypted_file`;

      console.log('Paths:', {
        inputPath,
        encryptedPath,
        decryptedPath,
      });

      // Write input text to file
      await RNFS.writeFile(inputPath, fileInputText, 'utf8');
      console.log('Written input file');

      // Verify input file was written
      const inputContent = await RNFS.readFile(inputPath, 'utf8');
      console.log('Input file content:', inputContent);

      // Encrypt
      console.log('Starting encryption...');
      await cipher.encryptFile(
        {
          algorithm: 'AES-GCM',
          key: fileEncryptionKey,
        },
        inputPath,
        encryptedPath
      );
      console.log('Encryption completed');

      // Verify encrypted file exists
      const encryptedExists = await RNFS.exists(encryptedPath);
      console.log('Encrypted file exists:', encryptedExists);

      // Decrypt
      console.log('Starting decryption...');
      await cipher.decryptFile(
        {
          algorithm: 'AES-GCM',
          key: fileEncryptionKey,
        },
        encryptedPath,
        decryptedPath
      );
      console.log('Decryption completed');

      // Verify decrypted file exists
      const decryptedExists = await RNFS.exists(decryptedPath);
      console.log('Decrypted file exists:', decryptedExists);

      // Read decrypted content
      const decryptedContent = await RNFS.readFile(decryptedPath, 'utf8');
      console.log('Decrypted content:', decryptedContent);
      setDecryptedFileContent(decryptedContent);

      // Clean up temporary files
      console.log('Cleaning up files...');
      await Promise.all([
        RNFS.unlink(inputPath),
        RNFS.unlink(encryptedPath),
        RNFS.unlink(decryptedPath),
      ]);
      console.log('Cleanup completed');

      setFileOperationStatus('Success! File encryption/decryption completed.');
    } catch (error: any) {
      console.error('Error encrypting/decrypting file:', error);
      // Log more details about the error
      console.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack,
      });
      setFileOperationStatus(`Error: ${error.message}`);
    }
  };

  const StringResultRow = ({
    label,
    value,
  }: {
    label: string;
    value: string;
  }) => (
    <View style={styles.resultRow}>
      <Text style={styles.resultLabel}>{label}:</Text>
      <View style={styles.resultValueContainer}>
        <Text selectable style={styles.resultText}>
          {value}
        </Text>
        <TouchableOpacity
          style={styles.copyButton}
          onPress={() => Clipboard.setString(value)}
        >
          <Text style={styles.copyButtonText}>Copy</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  const ResultRow = ({
    label,
    value,
  }: {
    label: string;
    value: Uint8Array;
  }) => (
    <View style={styles.resultRow}>
      <Text style={styles.resultLabel}>{label}:</Text>
      <View style={styles.resultValueContainer}>
        <Text selectable style={styles.resultText}>
          {
            label.includes('Decrypted')
              ? Buffer.from(value).toString('utf8') // Show decrypted value as string
              : Buffer.from(value).toString('base64') // Show encrypted value as base64
          }
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
    <ScrollView style={styles.scrollContainer}>
      <View style={styles.container}>
        <Text style={styles.title}>Encryption Tool</Text>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>String Encryption</Text>
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={inputText}
            onChangeText={setInputText}
            placeholder="Enter text to encrypt"
          />
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={stringEncryptionKey}
            onChangeText={setStringEncryptionKey}
            placeholder="Enter encryption key for string"
          />
          <TouchableOpacity style={styles.button} onPress={handleStringEncrypt}>
            <Text style={styles.buttonText}>Encrypt String</Text>
          </TouchableOpacity>
          {results.encrypted.length > 0 && (
            <>
              <StringResultRow
                label="Encrypted Text"
                value={results.encrypted}
              />
              <StringResultRow
                label="Decrypted Text"
                value={results.decrypted}
              />
            </>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Bytes Encryption</Text>
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={inputBytes}
            onChangeText={setInputBytes}
            placeholder="Enter message to encrypt as bytes"
          />
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={bytesEncryptionKey}
            onChangeText={setBytesEncryptionKey}
            placeholder="Enter encryption key for bytes"
          />
          <TouchableOpacity style={styles.button} onPress={handleBytesEncrypt}>
            <Text style={styles.buttonText}>Encrypt Bytes</Text>
          </TouchableOpacity>
          {results.bytesEncrypted.length > 0 && (
            <>
              <ResultRow
                label="Encrypted Bytes"
                value={results.bytesEncrypted}
              />
              <ResultRow
                label="Decrypted Bytes"
                value={results.bytesDecrypted}
              />
            </>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>File Encryption</Text>
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={fileInputText}
            onChangeText={setFileInputText}
            placeholder="Enter text to encrypt as file"
            multiline
            numberOfLines={4}
          />
          <TextInput
            style={[styles.input, styles.fullWidthInput]}
            value={fileEncryptionKey}
            onChangeText={setFileEncryptionKey}
            placeholder="Enter encryption key for file"
          />
          <TouchableOpacity
            style={styles.button}
            onPress={handleFileEncrypt}
            disabled={!fileInputText || !fileEncryptionKey}
          >
            <Text style={styles.buttonText}>Encrypt/Decrypt File</Text>
          </TouchableOpacity>
          {fileOperationStatus ? (
            <View style={styles.resultContainer}>
              <Text style={styles.resultText}>{fileOperationStatus}</Text>
            </View>
          ) : null}
          {decryptedFileContent ? (
            <View style={styles.resultContainer}>
              <Text style={styles.resultLabel}>Decrypted Content:</Text>
              <Text selectable style={[styles.resultText, { color: '#000' }]}>
                {decryptedFileContent}
              </Text>
            </View>
          ) : null}
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollContainer: {
    flex: 1,
  },
  container: {
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
    color: '#000',
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
    marginTop: 10,
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
