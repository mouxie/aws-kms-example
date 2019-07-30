package com.yanmouxie.aws.sdk.java.v1;

import java.io.IOException;
import java.net.URL;
import java.util.Scanner;
import java.io.InputStream;

public class KmsAwsSDKJavaV1 {

	public static void main(String[] args) {
		
		String textToEncrypt = "ABCDEF";
		
        String encryptedResult = EncryptionClient.encryptText(textToEncrypt);
        
        EncryptionClient.decryptText(encryptedResult);
        
        System.out.println(textToEncrypt);
	}

}
