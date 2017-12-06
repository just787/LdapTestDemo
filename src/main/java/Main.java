import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.query.LdapQuery;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

/**
 * LDAP验证用户名密码demo（各项配置在ldap.properties中）
 */
public class Main {
    private static LdapTemplate ldapTemplate;
    // 用户id属性名, 注:Windows Server 2003下的Ldap服务器的用户id名为sAMAccountName,且密码是不可见的
    private static String uidType = "uid";
    private static String uid = "wdl";
    private static String uPassword = "abCD";

    // 登录模板初始化
    static {
        Map<String, String> configMap = getConfigMap();
        uidType = configMap.get("ldap.uidtype");
        uid = configMap.get("ldap.uid");
        uPassword = configMap.get("ldap.upassword");

        LdapContextSource cs = new LdapContextSource();
        cs.setCacheEnvironmentProperties(false);
        //cs.setUrl("ldap://192.168.1.123:389");
        cs.setUrl(configMap.get("ldap.url"));
        //cs.setBase("dc=bsbpower,dc=com");
        cs.setBase(configMap.get("ldap.base"));

        final String password = configMap.get("ldap.password");
        final String username = configMap.get("ldap.username");

        cs.setAuthenticationSource(new AuthenticationSource() {
            // 密码
            public String getCredentials() {
                //return "secret";
                return password;
            }

            // 账户
            public String getPrincipal() {
                //return "cn=Manager,dc=bsbpower,dc=com";
                return username;
            }
        });

        ldapTemplate = new LdapTemplate(cs);
    }

    /**
     * 获取连接服务的配置值
     *
     * @return
     */
    public static Map<String, String> getConfigMap() {
        Map<String, String> map = new HashMap<String, String>();
        Properties pps = new Properties();
        try {
            InputStream in = new BufferedInputStream(new FileInputStream("./ldap.properties"));
            pps.load(in);
            Enumeration en = pps.propertyNames();
            while (en.hasMoreElements()) {
                String strKey = (String) en.nextElement();
                String strValue = pps.getProperty(strKey);
                map.put(strKey, strValue);
            }
        } catch (Exception e) {
            System.out.println(e);
        }

        return map;
    }

    // 获取用户信息
    public static List<String> getAllPersonNames() {
        LdapQuery query = query().where("objectclass").is("person"); //organizationalUnit

        List<String> result = ldapTemplate.search(query,
                new AttributesMapper<String>() {
                    public String mapFromAttributes(Attributes attributes) throws NamingException {
                        if (attributes != null) {
                            NamingEnumeration<?> answer = attributes.getAll();
                            while (answer.hasMore()) {
                                System.out.println(answer.nextElement());
                            }
                        }

                        System.out.println("-------------------------");
                        // attributes获取不到DN
                        return attributes.get("cn").get().toString();
                    }
                });

        return result;
    }

    /**
     * 用户id和密码验证
     *
     * @throws Exception
     */
    public static void authenticate() throws Exception {
        EqualsFilter filter = new EqualsFilter(uidType, uid);
        boolean b = ldapTemplate.authenticate("", filter.toString(), uPassword);
        System.out.println(filter.toString() + b);

       /* System.out.println("--------getContext test start");
        DirContext test = null;
        try {
            // 另一种验证方式
            test = ldapTemplate.getContextSource().getContext("CN=Ldap Ecoplus,OU=IT Test,OU=Other Group,OU=HEAD OFFICE,DC=smart,DC=local", "6e*uX0!@#");
        } catch (Exception e) {
            System.out.println("getContext:" + e);
        } finally {
            if (test != null) {
                test.close();
            }
        }
        System.out.println("--------getContext test end:" + test);*/
    }

    public static void main(String[] args) {
        System.out.println("-------------------start----------------------");
        //System.out.println(getAllPersonNames());
        System.out.println("\r\n------authenticate-----\r\n");
        try {
            authenticate();
        } catch (Exception e) {
            System.out.println("authenticate error:" + e);
        }
        System.out.println("-------------------end----------------------");
    }
}
