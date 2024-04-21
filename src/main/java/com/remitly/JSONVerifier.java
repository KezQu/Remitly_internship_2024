package com.remitly;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface JSONVerifier {
	static boolean verifyFile(String filepath){
		String file = loadFile(filepath);
		if (!checkPolicyName(file)){
			return false;
		}
		if (!checkPolicyDocument(file)){
			return false;
		}
		return true;
	}
	static boolean checkPolicyDocument(String file) {
		Pattern policyDocPat = Pattern.compile("\"PolicyDocument\": [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+");
		ArrayList<String> policyDocJSON = findSubsequences(policyDocPat, file);
		if(policyDocJSON.size() != 1){
			return false;
		}
		String policyDocument = policyDocJSON.getFirst();
		Pattern[] patternList = {
				Pattern.compile("\"Version\": \"[\\p{Digit}-]+\","),
				Pattern.compile("\"Statement\": \\p{Print}+"),
				Pattern.compile("(\"Sid\": \"\\p{Alnum}+\",){0,1}"),
				Pattern.compile("\"Effect\": \"Allow|Deny\","),
				Pattern.compile("(\"Principal\": \\p{Print}+,){0,1}"),
				Pattern.compile("\"Action\": (\\s*\"\\p{Alnum}+:\\p{Alnum}+\",)|(\\[(\\s*\"\\p{Alnum}+:\\p{Alnum}+\",)+(\\s*\"\\p{Alnum}+:\\p{Alnum}+\")\\s*\\],)"),
				Pattern.compile("(\"Resource\": \\p{Print}+){0,1}"),
				Pattern.compile("(\"Condition\": \\p{Print}+){0,1}")
		};
		for (Pattern pattern : patternList){
			if(findSubsequences(pattern, policyDocument).isEmpty()){
				return false;
			}
		}
		return true;
	}
	static boolean checkPolicyName(String file) {
		Pattern policyNamePat = Pattern.compile("\"PolicyName\": \"[\\w+=,.@-]+\"");
		return findSubsequences(policyNamePat, file).size() == 1;
	}
	static String loadFile(String filepath){
		StringBuffer fileBuffer = new StringBuffer();

		try(Scanner loader = new Scanner(new File(filepath))){
			while (loader.hasNextLine()){
				fileBuffer.append(loader.nextLine() + "\n");
			}
		}catch (FileNotFoundException e){
			System.out.println("File not found");
		}
		return fileBuffer.toString();
	}
	static ArrayList<String> findSubsequences(Pattern pattern, String file){
		Matcher matcher = pattern.matcher(file);
		ArrayList<String> matches = new ArrayList<>();
		while(matcher.find()){
			matches.add(matcher.group());
		}
		return matches;
	}
}