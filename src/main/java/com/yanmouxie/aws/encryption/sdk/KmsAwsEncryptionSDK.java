package com.yanmouxie.aws.encryption.sdk;

import java.util.Collections;
import java.util.Map;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

public class KmsAwsEncryptionSDK {

    final static String accessKeyId = "";
	final static String accessKeySecret = "";
	final static String keyArn = "";
    private static String data = "ABCDEF";
    
    public static void main(final String[] args) {
        
    	BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, accessKeySecret);
    	ClientConfiguration config = new ClientConfiguration();
    	config.setProxyHost("proxy.com");
    	config.setProxyPort(8080);
        
        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // Set up the KmsMasterKeyProvider   
        final KmsMasterKeyProvider prov = KmsMasterKeyProvider.builder()
        		.withClientBuilder(
        				AWSKMSClientBuilder
        				.standard()
        				.withCredentials(new AWSStaticCredentialsProvider(awsCreds))
        				.withClientConfiguration(config)
        				.withRegion(Regions.AP_SOUTHEAST_1))
        		.withKeysForEncryption(keyArn)
        		.build();

        // Encrypt the data
        //
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        //
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> context = Collections.singletonMap("Example", "String");

        final String ciphertext = crypto.encryptString(prov, data, context).getResult();
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the data
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        
        // Before returning the plaintext, verify that the customer master key that
        // was used in the encryption operation was the one supplied to the master key provider.  
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key ID!");
        }

        // Also, verify that the encryption context in the result contains the
        // encryption context supplied to the encryptString method. Because the
        // SDK can add values to the encryption context, don't require that 
        // the entire context matches. 
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }

        // Now we can return the plaintext data
        System.out.println("Decrypted: " + decryptResult.getResult());
    }
}
