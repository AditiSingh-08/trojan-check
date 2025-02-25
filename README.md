

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).

## Available Scripts

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in your browser.
# Web-Based Static File Analysis  

## *Project Overview*  
This project is a web applicationbthat performs *static analysis* on uploaded files to detect malware. It provides a clear verdict on whether a file is *benign, suspicious, or malicious* using various detection techniques.  

## *Steps to Use the Application*  

### *1. User File Upload*  
- The user accesses the *web interface*.  
- Uploads a file for *malware analysis*.  

### *2. Static Analysis Execution*  
- The backend *processes* the file using:  
  - *Signature-based detection* (YARA rules, VirusTotal).  
  - *Metadata extraction* (file type, size, headers).  
  - *Entropy analysis* (identifying packed or encrypted files).  
  - *Opcode & Bytecode pattern recognition*.  

### *3. Malware Detection & Categorization*  
- The system categorizes the file into:  
  - *Benign* (Safe)  
  - *Suspicious* (Potentially harmful)  
  - *Malicious* (Threat detected)  

### *4. Result Display*  
- The user gets a *detailed report* on the uploaded file.  
- Verdicts are *concise and easy to understand*.  



## *System Architecture*  

### *Frontend*  
- Framework: *React.js*  
- UI Library: *Material UI*  
- State Management: *POSTMAN API*  

### *Backend*  
- Language: Python
- Framework:  FastAPI
- Static Analysis Tools: YARA, PEfile, pyelftools, ClamAV 


### *Security Measures*  
- *Authentication:* JWT / OAuth  
- *API Security:* Rate limiting, request validation  







