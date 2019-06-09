package nl.reinkrul.quarkusca;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Path("/certificate/issue")
@Produces(MediaType.APPLICATION_JSON)
public class IssueCertificateResource {

    @Inject
    private CertificateAuthority certificateAuthority;

    @POST
    @Path("/server")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response issueServerCertificate(@FormParam("commonName") final String commonName,
                                           @FormParam("organization") final String organization,
                                           @FormParam("country") final String country) throws IOException {
        final KeyContainer container = certificateAuthority.issueServerCertificate(new CertificateRequest(commonName, organization, country));
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        container.store(data);
        return Response.ok(data.toByteArray(), MediaType.APPLICATION_OCTET_STREAM)
                       .header("Content-Disposition", "attachment; filename=" + commonName + KeyContainer.KEYSTORE_FILE_EXTENSION)
                       .build();
    }
}