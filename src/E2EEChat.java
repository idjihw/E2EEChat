import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class E2EEChat
{
    private Socket clientSocket = null;
    key key_ = new key();

    public Socket getSocketContext() {
        return clientSocket;
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    public E2EEChat() throws IOException {
       clientSocket = new Socket();
       clientSocket.connect(new InetSocketAddress(hostname, port));

       InputStream stream = clientSocket.getInputStream();

       Thread senderThread = new Thread(new MessageSender(this));
       senderThread.start();

       while (true) {
           try {
               if (clientSocket.isClosed() || !senderThread.isAlive()) {
                   break;
               }

               byte[] recvBytes = new byte[2048];
               int recvSize = stream.read(recvBytes);

               if (recvSize == 0) {
                   continue;
               }

               String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

               parseReceiveData(recv);
           } catch (IOException ex) {
               System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
               break;
           }
       }

       try {
           System.out.println("입력 스레드가 종료될때까지 대기중...");
           senderThread.join();

           if (clientSocket.isConnected()) {
               clientSocket.close();
           }
       } catch (InterruptedException ex) {
           System.out.println("종료되었습니다.");
       }
    }

    public void parseReceiveData(String recvData) {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.

	key key_ = new key();			
   	enc_dnc enc_dnc = new enc_dnc();
	String recv_message = "";

	if(recvData.split("\n")[0].equals("3EPROTO KEYXCHGOK")){	// 키가 승인되었을때
		key_.replace_key();					// tmp키에서 일반키로 저장
		key_.replace_IV();
	}
	
	if(recvData.split("\n")[0].equals("3EPROTO MSGRECV")){		// 메세지 수신 
		try{	
			recv_message = enc_dnc.decrypt(recvData.split("\n")[5]);	// 받은 데이터에서 메세지 부분을 decrypt해
		}catch(Exception ex){신
			ex.printStackTrace();
		}
		줌
		recvData.split("\n")[5] = recv_message;			// 이후 decrypt된 메세지로 교
	}

        System.out.println(recvData + "\n==== recv ====");
    }

    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

    public static void main(String[] args)
    {
        try {
            new E2EEChat();
        } catch (UnknownHostException ex) {
            System.out.println("연결 실패, 호스트 정보를 확인하세체요.");
        } catch (IOException ex) {
            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
        }
    }
}

class key{			// 키, IV 저장부분
	static String key;
	private String tmp_key;
	static String IV;
	private String tmp_IV;
	
	public void replace_key(){
		key = tmp_key;
	}

	public void set_key(String _key){
		key = _key;
	}

	public void set_tmp_key(String _key){
		tmp_key = tmp_key;
	}

	public static String get_key(){
		return key;
	}

	public void replace_IV(){
		IV = tmp_IV;
	}

	public void set_IV(String _IV){
		IV = _IV;
	}

	public void set_tmp_IV(String _IV){
		tmp_IV = _IV;
	}

	public static String get_IV(){
		return IV;
	}
}

class enc_dnc{			// 메세지의 dec, enc부분
	key key_ = new key();

	public String encrypt(String plainText) throws Exception {
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        	SecretKeySpec keySpec = new SecretKeySpec(key_.get_key().getBytes(), "AES");	// class key에서 key를 받아옴
        	IvParameterSpec ivParamSpec = new IvParameterSpec(key_.get_IV().getBytes());	// class key에서 IV를 받아옴
        	cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);
        
        	byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        	return Base64.getEncoder().encodeToString(encrypted);
   	}
    
   	public String decrypt(String cipherText) throws Exception {
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        	SecretKeySpec keySpec = new SecretKeySpec(key_.get_key().getBytes(), "AES");
        	IvParameterSpec ivParamSpec = new IvParameterSpec(key_.get_IV().getBytes());
        	cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);
        
       		byte[] decodedBytes =  Base64.getDecoder().decode(cipherText);
        	byte[] decrypted = cipher.doFinal(decodedBytes);
        	return new String(decrypted, "UTF-8");
   	}
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;
    
    String tmp_key;
    String tmp_IV;
    String enc_text = "";

    key key_ = new key();
    enc_dnc enc_dnc = new enc_dnc();
    
    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            try {
                System.out.print("MESSAGE: ");

                String message = scanner.nextLine().trim();
	
		if(message.split("\n")[0].equals("3EPROTO KEYXCHG")){	// 키와 IV교환. deny됐을 경우를 생각해 tmp에 저장해줍니다.
			tmp_key = message.split("\n")[5];
			key_.set_tmp_key(tmp_key);
			tmp_IV = message.split("\n")[6];
			key_.set_tmp_IV(tmp_IV);
		}

		if(message.split("\n")[0].equals("3EPROTO KEYXCHGRST")){	// 키 바꿈 요청
			tmp_key = message.split("\n")[5];
			key_.set_tmp_key(tmp_key);
			tmp_IV = message.split("\n")[6];
			key_.set_tmp_IV(tmp_IV);
		}

		if(message.split("\n")[0].equals("3EPROTO MSGSEND")){	// 메세지 교
			try{
				enc_text = enc_dnc.encrypt(message.split("\n")[5]);	// 보내는 메세지를 받아 encrypt 해줍니다
			}catch(Exception ex){환
				ex.printStackTrace();
			}
			
			message.split("\n")[5] = enc_text;	// 이후 메세지를 enc된 상태로 보내줍니다.
		}


                byte[] payload = message.getBytes(StandardCharsets.UTF_8);

                socketOutputStream.write(payload, 0, payload.length);
            } catch (IOException ex) {
                break;
            }
        }

        System.out.println("MessageSender runnable end");
    }
}
