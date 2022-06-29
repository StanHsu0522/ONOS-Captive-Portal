package nctu.winlab.authentication;

import org.onlab.rest.AbstractWebApplication;
import java.util.Set;

public class AuthWebApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(AuthWebResource.class);
    }
}