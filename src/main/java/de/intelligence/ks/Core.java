package de.intelligence.ks;

import picocli.CommandLine;

public final class Core {

    public static void main(String[] args) {
        System.exit(new CommandLine(new KeystoreCommand()).execute(args));
    }

}
