package com.remitly;

import org.junit.jupiter.api.Test;

import java.io.*;

import static org.junit.jupiter.api.Assertions.*;

class JSONVerifierTest {
	@Test
	void verifyFile_WrongFile() {
		assertFalse(JSONVerifier.verifyFile("wrong/filepath.NOSJ"));
	}
	@Test
	void verifyFile_EmptyFile() {
		File tmpFile = new File("tmpTestEmptyFile.JSON");
		assertFalse(JSONVerifier.verifyFile("tmpTestEmptyFile.JSON"));
		tmpFile.delete();
	}
	@Test
	void checkPolicyDocument_WrongPolicyDocument() {
		assertFalse(JSONVerifier.checkPolicyDocument("""
				{ "PolicyName": "root", "PolicyDocument": }"""));
		assertFalse(JSONVerifier.checkPolicyDocument("""
				{ "PolicyName": "root", "PolicyDocument" }"""));
		assertFalse(JSONVerifier.checkPolicyDocument("""
				{ "PolicyName": "root", }"""));
	}
	@Test
	void checkPolicyDocument_WrongVersion() {
		String[] wrongVersion = {"\"Version\": \"\",","", "\"Version\": \"sdgfvc\","};
		for (String version : wrongVersion){
			assertFalse(JSONVerifier.checkPolicyDocument("""
					{
					  "PolicyName": "root",
					  "PolicyDocument": {
					""" + version + """
					    "Statement": [
					      {
					        "Sid": "IamListAccess",
					        "Effect": "Allow",
					        "Action": [
					          "iam:ListRoles",
					          "iam:ListUsers"
					        ],
					        "Resource": "*"
					      }
					    ]
					  }
					}
					"""));
		}
	}
	@Test
	void checkPolicyDocument_WrongEffect() {
		String[] wrongEffect = {"\"Effect\": \"\",", "\"Effect\": \"asdvc\",","","\"Effect\": \"\"",};
		for (String effect : wrongEffect){
			assertFalse(JSONVerifier.checkPolicyDocument("""
					{
					  "PolicyName": "root",
					  "PolicyDocument": {
					    "Version": "2012-10-17",
					    "Statement": [
					      {
					        "Sid": "IamListAccess",
					""" + effect + """
					        "Action": [
					          "iam:ListRoles",
					          "iam:ListUsers"
					        ],
					        "Resource": "*"
					      }
					    ]
					  }
					}
					"""));
		}
	}
	@Test
	void checkPolicyDocument_WrongAction() {
		String[] wrongActions = {"""
        "Action": [
          "iam:ListRoles",
          "iam:ListUsers"
        ]
""", """
        "Action": [
        ],
""", """
        "Action": [
          "iam:ListRoles"
          "iam:ListUsers"
        ]
""", """
        "Action": [
          "iam:ListRoles"
          "iam:ListUsers"
""", ""};
		for (String action : wrongActions){
			assertFalse(JSONVerifier.checkPolicyDocument("""
					{
					  "PolicyName": "root",
					  "PolicyDocument": {
					    "Version": "2012-10-17",
					    "Statement": [
					      {
					        "Sid": "IamListAccess",
					        "Effect": "Allow",
					""" + action + """
					        "Resource": "*"
					      }
					    ]
					  }
					}
					"""));
		}
	}
	@Test
	void checkPolicyName() {
		assertFalse(JSONVerifier.checkPolicyName("\"PolicyName\": \"\","));
		assertFalse(JSONVerifier.checkPolicyName(""));
		assertFalse(JSONVerifier.checkPolicyName("\"PolicyName\": \","));
	}

	@Test
	void loadFile_FileNotFound() {
		PrintStream oldOut = System.out;
		ByteArrayOutputStream newOut = new ByteArrayOutputStream();
		System.setOut(new PrintStream(newOut));
		JSONVerifier.verifyFile("wrong/filepath.NOSJ");
		assertTrue(newOut.toString().contains("File not found"));
		System.setOut(oldOut);
	}

	@Test
	void correctOutput() {
		String content = """
				{
				  "PolicyName": "root",
				  "PolicyDocument": {
				    "Version": "2012-10-17",
				    "Statement": [
				      {
				        "Sid": "IamListAccess",
				        "Effect": "Allow",
				        "Action": [
				          "iam:ListRoles",
				          "iam:ListUsers"
				        ],
				        "Resource": "*"
				      }
				    ]
				  }
				}
				""";
		File tmpFile = new File("correct.JSON");
		try(FileWriter fio = new FileWriter(tmpFile)){
			fio.write(content);
		}catch (IOException ignored) {}
		assertTrue(JSONVerifier.verifyFile(tmpFile.getName()));
		tmpFile.delete();
	}
}