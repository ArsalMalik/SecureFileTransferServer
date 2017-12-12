import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.awt.Color;
import java.io.*;

public class FileServer extends JFrame {
	private static final int PORT = 6689;
	//private static final String FILENAME = "/home/dell/nmap_results.txt";
	//private static final String UPLOAD_FILENAME = "/home/dell/msg1_client.txt";
	//private static final String SERVER_CERT_PATH = "server-certificate.crt";
	private static final long serialVersionUID = 1L;
	//private JTextField userText;
	private static JTextArea Window;
	private JPanel Panel;
	//private ObjectOutputStream output;
	//private ObjectInputStream input;
	private static ServerSocket socket;
	private static Socket clientSocket;
	private static InputStream is;
	private static OutputStream os;
	private static DataInputStream dis;
	//private static FileOutputStream fos;
	private static BufferedOutputStream bos;
	private static DataOutputStream dos;
	//private static FileInputStream fis;
	private static BufferedInputStream bis;
	private FileTransferProtocolServer protocol = new FileTransferProtocolServer();

	//constructor
	public FileServer() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
		//Setting up the GUI
		setTitle("SERVER - File Transfer Protocol");
		Window = new JTextArea();			
		Panel = new JPanel();									// The main panel that consists of all of the above
		JScrollPane scrollPane = new JScrollPane(Window);	// Scroll panel for the chat window
		this.setSize(500, 500);									// setting the size of the whole window
		this.setVisible(true);									// setting its visibility as true
		Panel.setLayout(null);									//setting layout as null
		this.add(Panel);										// adding panel to out window
		scrollPane.setBounds(10, 10, 460, 430);					// setting bounds for the scroll panel that is attched to the chatwindow	
		Panel.add(scrollPane);
		Window.setBackground(Color.LIGHT_GRAY);
		Window.setForeground(Color.BLUE );
		Window.setBorder(BorderFactory.createLineBorder(Color.black));
		Window.setEditable(false);										//so that no one can edit the chat history
		Window.setLineWrap(true);
		//userText.setBorder(BorderFactory.createLineBorder(Color.black));
		protocol.setServerPrivateKey(this.getPrivate());
		
	}

	//set up server
	public void  startRunning() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
		try{
			socket = new ServerSocket(PORT);
			waitForConnection();	//Function for listening and accepting incoming connections
			setupStreams();			//Function for setting up i/p & o/p streams
			protocol.receiveNonce(dis);
			String option;
			while(true) {
				option = dis.readUTF();
				if(option.equals("upload")) {
					String fileName = dis.readUTF();
					protocol.receiveFileFromClient(clientSocket, dis, fileName);
				}
				
				else if(option.equals("List Server Files")) {
					File homeDir = new File(".");
					String fileNamesStr = "\n";
					for(File file: homeDir.listFiles()) {
						if(!file.isDirectory() && !file.isHidden()) {
							fileNamesStr = fileNamesStr.concat(file.getName()).concat("\t");
						}
					}
					System.out.println("File names: \n"+fileNamesStr);
					dos.writeUTF(fileNamesStr);
					String fileName = dis.readUTF();
					File file = new File(fileName);
					protocol.sendFileToClient(socket, dis, dos, file);
				}
				
			}
			//sendCertificate();
			} catch (EOFException e){
				showMessage("\n Connection terminated!");    //When user disconnects
//				} catch (ClassNotFoundException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}//sendCertificate();
			
	}	

	//wait for user to connect
	private void waitForConnection() throws IOException {
		showMessage("Waiting for someone to connect...\n");
		clientSocket = socket.accept(); 									// accept connection request
		showMessage(" Connected to " + clientSocket.getInetAddress().getHostName() + "\n\n");   // print the host Name that is connected
	}



	private void receiveFromClient() throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		String message = "-----------------------------------------" 
				+ "-----------------------------------------";
		showMessage(message);
		String uploadFileName = dis.readUTF();
		protocol.receiveFileFromClient(clientSocket, dis, uploadFileName);
	}

	private void setupStreams() throws IOException {
		is = clientSocket.getInputStream();
		os = clientSocket.getOutputStream();
		dis = new DataInputStream(clientSocket.getInputStream());
		//FileOutputStream fos = new FileOutputStream(UPLOAD_FILENAME);
		//BufferedOutputStream bos = new BufferedOutputStream(fos);
		dos = new DataOutputStream(os);
		//FileInputStream fis = new FileInputStream(FILENAME);
		//BufferedInputStream bis = new BufferedInputStream(fis);
	}

	//display messages
	public static void showMessage(final String text){
		SwingUtilities.invokeLater(
				new Runnable(){
					public void run(){
						Window.append(text);				// add sent messages to the chat history window
					}
				}
				);
	}



	private void closeAllConnections() throws IOException {
		is.close();
		os.close();
		dis.close();
		//fos.close();
		if(bos != null)
		{
			bos.close();
		}
		dos.flush();
		dos.close();
		//fis.close();
		if(bis != null) {
			bis.close();
		}
	}

	private PrivateKey getPrivate() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		//Generating key spec of the server's private key
		String privateKeyStr = new String(Files.readAllBytes(Paths.get("server_privatekey"))).trim();
		privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("-----END PRIVATE KEY-----","").trim();
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey serverPrivateKey = kf.generatePrivate(spec);
		return serverPrivateKey;
	}

	// Upload to server
	/*byte[] fileByte = new byte[64];
    		int bytesRead = 0;
    		while(bytesRead != -1) {
    			bytesRead = dis.read(fileByte,0,fileByte.length);
    			if(bytesRead > 0) {
    				bos.write(fileByte,0,bytesRead);
    			}
    		}*/

	//Download from server
	/*byte[] fileByte = new byte[64];
			int bytesRead = 0;
			while(bytesRead != -1) {
				bytesRead = bis.read(fileByte, 0, fileByte.length);
				if(bytesRead > 0)
				{
					dos.write(fileByte,0,bytesRead);
				}
			}*/

	// Send certificate to client
	/*private void sendCertificate()throws IOException, FileNotFoundException{
		FileInputStream certFis = new FileInputStream(SERVER_CERT_PATH);
		BufferedInputStream certBis = new BufferedInputStream(certFis);
		byte[] fileByte = new byte[64];
		int bytesRead = 0;
		while(bytesRead != -1) {
			bytesRead = certBis.read(fileByte, 0, fileByte.length);
			if(bytesRead > 0)
			{
				dos.write(fileByte,0,bytesRead);
			}
		}
		//certBis.close();
		int rec = dis.readInt();
		System.out.println("Integer received from client: "+rec);
		dis.close();
		certBis.close();
	}*/
}

