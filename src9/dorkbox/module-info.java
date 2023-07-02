module dorkbox.crypto {
    exports dorkbox.crypto;
    exports dorkbox.crypto.signers;

    requires transitive dorkbox.updates;

    requires static org.bouncycastle.provider;
    requires static org.slf4j;

    requires transitive kotlin.stdlib;
}
