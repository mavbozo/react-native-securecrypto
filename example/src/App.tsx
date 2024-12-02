import { StyleSheet, View, Text, TouchableOpacity } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { enableScreens } from 'react-native-screens';
import Encryption from './pages/Encryption';
import RandomBytes from './pages/RandomBytes';
import KeyDerivation from './pages/KeyDerivation';

enableScreens();

const Stack = createStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator>
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="Encryption" component={Encryption} />
        <Stack.Screen name="RandomBytes" component={RandomBytes} />
        <Stack.Screen name="KeyDerivation" component={KeyDerivation} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

function HomeScreen({ navigation }: { navigation: any }) {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Crypto Tools</Text>
      <TouchableOpacity
        style={styles.button}
        onPress={() => navigation.navigate('Encryption')}
      >
        <Text style={styles.buttonText}>Encryption</Text>
      </TouchableOpacity>
      <TouchableOpacity
        style={styles.button}
        onPress={() => navigation.navigate('RandomBytes')}
      >
        <Text style={styles.buttonText}>Random Bytes Generator</Text>
      </TouchableOpacity>
      <TouchableOpacity
        style={styles.button}
        onPress={() => navigation.navigate('KeyDerivation')}
      >
        <Text style={styles.buttonText}>Key Derivation</Text>
      </TouchableOpacity>
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
