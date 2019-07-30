package com.yanmouxie.aws.sdk.java.v1;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class EncryptionClient {

	final static String accessKeyId = "";
	final static String accessKeySecret = "";
	final static String keyArn = "";

    public static String encryptText(String textToEncrypt) {
    	BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, accessKeySecret);
    	
    	ClientConfiguration config = new ClientConfiguration();
    	config.setProxyHost("proxy.com");
    	config.setProxyPort(8080);
    	AWSKMSClientBuilder newBuilder = AWSKMSClient.builder();
    	newBuilder.setClientConfiguration(config);
    	
    	AWSKMS awskmsClient = newBuilder
    			.withCredentials(new AWSStaticCredentialsProvider(awsCreds))
    			.withRegion(Regions.AP_SOUTHEAST_1)
    			//.withEndpointConfiguration(new EndpointConfiguration("https://vpc-123456.kms.ap-southeast-1.vpce.amazonaws.com", "ap-southeast-1"))
    			.build();
        //AWSKMSClient awskmsClient = new AWSKMSClient(new Credentials());

        ByteBuffer plainText = ByteBuffer.wrap(textToEncrypt.getBytes());
        EncryptRequest request = new EncryptRequest().withKeyId(keyArn).withPlaintext(plainText);

        EncryptResult encryptResult = awskmsClient.encrypt(request);
        ByteBuffer cipherTextBlob = encryptResult.getCiphertextBlob();

        System.out.println("------------ ENCRYPTED RESULT BE ENCODED WITH BASE64 ------------");
        String base64String = Utils.encodeBase64String(cipherTextBlob.array());
        System.out.println(base64String);

        return base64String;
    }

    public static String decryptText(String textToDecrypt) {
    	
    	BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, accessKeySecret);
    	
    	ClientConfiguration config = new ClientConfiguration();
    	config.setProxyHost("proxy.com");
    	config.setProxyPort(8080);
    	AWSKMSClientBuilder newBuilder = AWSKMSClient.builder();
    	newBuilder.setClientConfiguration(config);
    	
    	AWSKMS awskmsClient = newBuilder
    			.withCredentials(new AWSStaticCredentialsProvider(awsCreds))
    			.withRegion(Regions.AP_SOUTHEAST_1)
    			//.withEndpointConfiguration(new EndpointConfiguration("https://vpc-123456.kms.ap-southeast-1.vpce.amazonaws.com", "ap-southeast-1"))
    			.build();
    	//AWSKMS awskmsClient = AWSKMSClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(awsCreds)).withRegion(Regions.AP_SOUTHEAST_1).build();
    	
        //AWSKMSClient awskmsClient = new AWSKMSClient(new Credentials());

    	byte[] tmpBytes = Utils.decodeBase64String(textToDecrypt);
    	ByteBuffer ciphertextBlob = ByteBuffer.wrap(tmpBytes);
        DecryptRequest req = new DecryptRequest().withCiphertextBlob(ciphertextBlob);

        DecryptResult decryptResult = awskmsClient.decrypt(req);
        ByteBuffer byteBuffer = decryptResult.getPlaintext();

        System.out.println("------------ DECRYPTED RESULT ------------");
        String text = new String( byteBuffer.array(), StandardCharsets.UTF_8 );
        System.out.println(text);

        return text;
    }
}
