package com.remitly;

import java.util.Scanner;

public class App {
	public static void main(String[] args) {
		Scanner commandLineReader = new Scanner(System.in);
		System.out.print("Enter JSON file name: ");
		System.out.println("Result: " + JSONVerifier.verifyFile(commandLineReader.nextLine()));
	}
}