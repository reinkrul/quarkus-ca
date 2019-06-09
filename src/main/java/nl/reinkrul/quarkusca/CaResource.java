package nl.reinkrul.quarkusca;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;

@Path("/ca")
public class CaResource {

    @Inject
    private CertificateAuthority certificateAuthority;

    @GET
    @Path("/certificate")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getCertificate() throws IOException {
        final StringWriter buffer = new StringWriter();
        try (PemWriter writer = new PemWriter(buffer)) {
            writer.writeObject(new PemObject("CERTIFICATE", certificateAuthority.getCertificate().getEncoded()));
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return Response.ok(buffer.toString(), MediaType.APPLICATION_OCTET_STREAM)
                       .header("Content-Disposition", "attachment; filename=ca-certificate.pem")
                       .build();
    }
}