package nl.reinkrul.quarkusca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class CertificateRequest {

    public final String commonName;
    public final String organization;
    public final String country;

    public CertificateRequest(final String commonName, final String organization, final String country) {
        this.commonName = commonName;
        this.organization = organization;
        this.country = country;
    }

    @Override
    public String toString() {
        return "CertificateRequest{" +
                "commonName='" + commonName + '\'' +
                ", organization='" + organization + '\'' +
                ", country='" + country + '\'' +
                '}';
    }

    public X500Name toX500Name() {
        final X500NameBuilder builder = new X500NameBuilder().addRDN(BCStyle.CN, commonName);
        if (organization != null && !organization.isEmpty()) {
            builder.addRDN(BCStyle.O, organization);
        }
        if (country != null && !country.isEmpty()) {
            builder.addRDN(BCStyle.C, country);
        }
        return builder.build();
    }
}

