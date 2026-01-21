module dorkbox.crypto {
    exports dorkbox.crypto;
    exports dorkbox.crypto.signers;

    requires transitive dorkbox.updates;

    requires static org.bouncycastle.provider;
    requires static org.bouncycastle.pg;
    requires static org.bouncycastle.pkix;
    requires static org.bouncycastle.util;
    requires static org.slf4j;

    requires transitive kotlin.stdlib;
}
