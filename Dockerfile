# CyberRange - Simplified Single Container Deployment
FROM node:18-alpine AS builder

WORKDIR /app

# Create package.json
RUN cat > package.json << 'EOF'
{
  "name": "cyberrange",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lucide-react": "^0.263.1"
  },
  "scripts": {
    "build": "webpack --mode production"
  },
  "devDependencies": {
    "@babel/core": "^7.22.0",
    "@babel/preset-react": "^7.22.0",
    "babel-loader": "^9.1.2",
    "css-loader": "^6.8.1",
    "html-webpack-plugin": "^5.5.3",
    "style-loader": "^3.3.3",
    "webpack": "^5.88.0",
    "webpack-cli": "^5.1.4"
  }
}
EOF

# Install dependencies
RUN npm install

# Create webpack config
RUN cat > webpack.config.js << 'EOF'
const HtmlWebpackPlugin = require('html-webpack-plugin');
const path = require('path');

module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.[contenthash].js',
    clean: true
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-react']
          }
        }
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ]
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './public/index.html'
    })
  ],
  resolve: {
    extensions: ['.js', '.jsx']
  }
};
EOF

# Create directory structure
RUN mkdir -p src public

# Create HTML template
RUN cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#000000" />
  <meta name="description" content="CyberRange - Ethical Hacking Training Platform" />
  <title>CyberRange</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
  <noscript>You need to enable JavaScript to run this app.</noscript>
  <div id="root"></div>
</body>
</html>
EOF

# Create index.js
RUN cat > src/index.js << 'EOF'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOF

# Create App.js
RUN cat > src/App.js << 'APPEOF'
import React, { useState } from 'react';
import { Shield, Terminal, Lock, Search, Network, AlertTriangle, FileText, Key, Wifi, Bug, Activity } from 'lucide-react';

const CyberRange = () => {
  const [activeScenario, setActiveScenario] = useState(null);
  const [terminalOutput, setTerminalOutput] = useState([]);
  const [commandInput, setCommandInput] = useState('');

  const scenarios = [
    {
      id: 'web-vuln',
      title: 'Web Application Vulnerabilities',
      icon: Bug,
      difficulty: 'Beginner',
      description: 'Learn to identify and exploit common web vulnerabilities including SQL injection, XSS, and CSRF.',
      tools: ['Burp Suite', 'SQLMap', 'OWASP ZAP'],
      challenges: ['SQL Injection', 'Cross-Site Scripting', 'CSRF Token Bypass']
    },
    {
      id: 'network-recon',
      title: 'Network Reconnaissance',
      icon: Network,
      difficulty: 'Intermediate',
      description: 'Master network scanning, enumeration, and information gathering techniques.',
      tools: ['Nmap', 'Wireshark', 'Netcat', 'Masscan'],
      challenges: ['Port Scanning', 'Service Enumeration', 'Network Mapping']
    },
    {
      id: 'password-cracking',
      title: 'Password Cracking & Hash Analysis',
      icon: Key,
      difficulty: 'Intermediate',
      description: 'Crack passwords and analyze cryptographic hashes using various techniques.',
      tools: ['John the Ripper', 'Hashcat', 'Hydra', 'CrackStation'],
      challenges: ['MD5 Hash Cracking', 'SSH Brute Force', 'Rainbow Tables']
    },
    {
      id: 'wireless-attacks',
      title: 'Wireless Network Security',
      icon: Wifi,
      difficulty: 'Advanced',
      description: 'Explore WiFi security, WPA/WPA2 cracking, and rogue access point detection.',
      tools: ['Aircrack-ng', 'Reaver', 'Wifite', 'Kismet'],
      challenges: ['WPA2 Handshake Capture', 'Evil Twin Attack', 'Deauth Attack']
    },
    {
      id: 'dfir-forensics',
      title: 'Digital Forensics Investigation',
      icon: Search,
      difficulty: 'Advanced',
      description: 'Analyze disk images, memory dumps, and investigate security incidents.',
      tools: ['Autopsy', 'Volatility', 'FTK Imager', 'Sleuth Kit'],
      challenges: ['Memory Analysis', 'Timeline Creation', 'Evidence Recovery']
    },
    {
      id: 'malware-analysis',
      title: 'Malware Analysis Lab',
      icon: AlertTriangle,
      difficulty: 'Expert',
      description: 'Reverse engineer malware samples in a safe, isolated environment.',
      tools: ['IDA Pro', 'Ghidra', 'x64dbg', 'Process Monitor'],
      challenges: ['Static Analysis', 'Dynamic Analysis', 'Behavior Monitoring']
    },
    {
      id: 'log-analysis',
      title: 'Log Analysis & SIEM',
      icon: FileText,
      difficulty: 'Intermediate',
      description: 'Parse system logs, detect anomalies, and respond to security events.',
      tools: ['Splunk', 'ELK Stack', 'Grep', 'Regex'],
      challenges: ['Brute Force Detection', 'Lateral Movement', 'Data Exfiltration']
    },
    {
      id: 'exploit-dev',
      title: 'Exploit Development',
      icon: Terminal,
      difficulty: 'Expert',
      description: 'Learn buffer overflows, ROP chains, and binary exploitation techniques.',
      tools: ['GDB', 'pwntools', 'ROPgadget', 'Metasploit'],
      challenges: ['Stack Buffer Overflow', 'Return-to-libc', 'Format String']
    },
    {
      id: 'incident-response',
      title: 'Incident Response Simulation',
      icon: Activity,
      difficulty: 'Advanced',
      description: 'Respond to live security incidents following NIST frameworks.',
      tools: ['Velociraptor', 'KAPE', 'Sysmon', 'TheHive'],
      challenges: ['Ransomware Response', 'APT Detection', 'Containment Strategy']
    }
  ];

  const handleCommand = (e) => {
    if (e) e.preventDefault();
    if (!commandInput.trim()) return;

    const newOutput = [...terminalOutput, { type: 'input', text: `$ ${commandInput}` }];
    
    const responses = {
      'help': 'Available commands: nmap, sqlmap, hydra, john, aircrack-ng, volatility, help, clear',
      'nmap': 'Starting Nmap 7.94 ( https://nmap.org )\nScanning target 192.168.1.100...\nPORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http\n443/tcp open  https',
      'sqlmap': 'sqlmap resumed the following injection point(s):\n---\nParameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind - WHERE or HAVING clause',
      'hydra': '[22][ssh] host: 192.168.1.100   login: admin   password: password123\n1 of 1 target successfully completed, 1 valid password found',
      'clear': null
    };

    if (commandInput.toLowerCase() === 'clear') {
      setTerminalOutput([]);
    } else {
      const response = responses[commandInput.toLowerCase()] || `Command '${commandInput}' executed. Check the scenario documentation for detailed output.`;
      newOutput.push({ type: 'output', text: response });
      setTerminalOutput(newOutput);
    }
    
    setCommandInput('');
  };

  const getDifficultyColor = (difficulty) => {
    const colors = {
      'Beginner': 'bg-green-500',
      'Intermediate': 'bg-yellow-500',
      'Advanced': 'bg-orange-500',
      'Expert': 'bg-red-500'
    };
    return colors[difficulty] || 'bg-gray-500';
  };

  return (
    <div className="min-h-screen bg-white">
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900"></div>
        <div className="relative max-w-7xl mx-auto px-6 py-24 text-center">
          <div className="flex justify-center mb-6">
            <Shield className="w-20 h-20 text-blue-400" strokeWidth={1.5} />
          </div>
          <h1 className="text-6xl font-semibold text-white mb-6 tracking-tight">CyberRange</h1>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto font-light">
            Master ethical hacking and digital forensics in a safe, controlled environment.
            Train like a pro. Think like an attacker. Defend like a champion.
          </p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-20">
        <h2 className="text-4xl font-semibold text-gray-900 mb-4 text-center">Training Scenarios</h2>
        <p className="text-center text-gray-600 mb-16 text-lg">Choose your path and start training</p>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {scenarios.map((scenario) => {
            const Icon = scenario.icon;
            return (
              <div
                key={scenario.id}
                onClick={() => setActiveScenario(scenario)}
                className="group bg-white rounded-3xl p-8 cursor-pointer transition-all duration-300 hover:shadow-2xl border border-gray-200 hover:scale-105"
              >
                <div className="flex items-center justify-between mb-4">
                  <Icon className="w-12 h-12 text-blue-600" strokeWidth={1.5} />
                  <span className={`text-xs font-medium px-3 py-1 rounded-full text-white ${getDifficultyColor(scenario.difficulty)}`}>
                    {scenario.difficulty}
                  </span>
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">{scenario.title}</h3>
                <p className="text-gray-600 text-sm leading-relaxed mb-4">{scenario.description}</p>
                <div className="flex flex-wrap gap-2">
                  {scenario.tools.slice(0, 3).map((tool, idx) => (
                    <span key={idx} className="text-xs bg-gray-100 text-gray-700 px-3 py-1 rounded-full">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {activeScenario && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-6 z-50" onClick={() => setActiveScenario(null)}>
          <div className="bg-white rounded-3xl max-w-5xl w-full max-h-[90vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
            <div className="p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                  {React.createElement(activeScenario.icon, { className: "w-10 h-10 text-blue-600" })}
                  <div>
                    <h3 className="text-3xl font-semibold text-gray-900">{activeScenario.title}</h3>
                    <span className={`inline-block mt-2 text-xs font-medium px-3 py-1 rounded-full text-white ${getDifficultyColor(activeScenario.difficulty)}`}>
                      {activeScenario.difficulty}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setActiveScenario(null)}
                  className="text-gray-400 hover:text-gray-600 text-2xl font-bold leading-none"
                >
                  ×
                </button>
              </div>

              <p className="text-gray-600 mb-6">{activeScenario.description}</p>

              <div className="mb-6">
                <h4 className="text-lg font-semibold text-gray-900 mb-3">Available Tools</h4>
                <div className="flex flex-wrap gap-2">
                  {activeScenario.tools.map((tool, idx) => (
                    <span key={idx} className="bg-blue-50 text-blue-700 px-4 py-2 rounded-full text-sm font-medium">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mb-6">
                <h4 className="text-lg font-semibold text-gray-900 mb-3">Challenges</h4>
                <div className="space-y-2">
                  {activeScenario.challenges.map((challenge, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl">
                      <Lock className="w-5 h-5 text-gray-400" />
                      <span className="text-gray-700">{challenge}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-gray-900 rounded-2xl overflow-hidden">
                <div className="bg-gray-800 px-4 py-3 flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500"></div>
                  <span className="ml-4 text-gray-400 text-sm">Terminal - {activeScenario.title}</span>
                </div>
                <div className="p-4 h-64 overflow-auto font-mono text-sm">
                  <div className="text-green-400 mb-2">
                    CyberRange Training Environment v1.0<br />
                    Type 'help' for available commands
                  </div>
                  {terminalOutput.map((line, idx) => (
                    <div key={idx} className={line.type === 'input' ? 'text-white' : 'text-gray-400'}>
                      {line.text}
                    </div>
                  ))}
                  <div className="flex items-center">
                    <span className="text-green-400 mr-2">$</span>
                    <input
                      type="text"
                      value={commandInput}
                      onChange={(e) => setCommandInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          handleCommand(e);
                        }
                      }}
                      className="flex-1 bg-transparent text-white outline-none"
                      placeholder="Enter command..."
                      autoFocus
                    />
                  </div>
                </div>
              </div>

              <div className="mt-6 flex gap-4">
                <button className="flex-1 bg-blue-600 text-white py-3 px-6 rounded-full font-medium hover:bg-blue-700 transition-colors">
                  Start Scenario
                </button>
                <button className="px-6 py-3 border border-gray-300 rounded-full font-medium hover:bg-gray-50 transition-colors">
                  Documentation
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-6 text-center">
          <p className="text-gray-600">Built for ethical hackers, security professionals, and DFIR analysts</p>
          <p className="text-sm text-gray-500 mt-2">Always practice responsible disclosure and obtain proper authorization</p>
        </div>
      </div>
    </div>
  );
};

export default CyberRange;
APPEOF

# Build the app
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Configure nginx
RUN cat > /etc/nginx/conf.d/default.conf << 'EOF'
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
}
EOF

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]