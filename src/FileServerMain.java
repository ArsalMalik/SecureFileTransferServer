import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;

public class FileServerMain {
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
		FileServer server = new FileServer();										//Create new server class instance
		server.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);				//Exit the window on closing connection
		server.startRunning();												//Invoke the function to set up everything
	}
}
