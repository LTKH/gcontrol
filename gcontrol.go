package main

import (
	"os"
    "os/signal"
	"syscall"
	"flag"
	"time"
    "log"
    "fmt"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"github.com/naoina/toml"
    "github.com/go-ldap/ldap/v3"
)

type Config struct {
    Grafana         Grafana                 `toml:"grafana"`
    Servers         []Server                `toml:"servers"`
}

type Grafana struct {
    Url             string                  `toml:"url"`
    User            string                  `toml:"user"`
    Password        string                  `toml:"password"`
    CertFile        string                  `toml:"cert_file"`
    CertKey         string                  `toml:"cert_key"`
}

type Server struct {
    User            string                  `toml:"user"`
    Password        string                  `toml:"password"`
    Host            string                  `toml:"host"`
    Port            int                     `toml:"port"`
    BindDn          string                  `toml:"bind_dn"`
    SearchFilter    string                  `toml:"search_filter"`
    SearchBaseDns   []string                `toml:"search_base_dns"`
    GroupMappings   []GroupMapping          `toml:"group_mappings"`
    Attributes      map[string]string       `toml:"attributes"`
    Conn            *ldap.Conn
}

type GroupMapping struct {
    GroupDn            string                  `toml:"group_dn"`
    OrgId              int                     `toml:"org_id"`
    TeamId             int                     `toml:"team_id"`
}

type Login struct {
    User               string                  `json:"user"`
    Password           string                  `json:"password"`
}

// Connect connects to the ldap backend.
func (s *Server) LdapNew() error {

    conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port))
    if err != nil {
        return err
    }
    
    if err := conn.Bind(fmt.Sprintf(s.BindDn, s.User), s.Password); err != nil {
        return err
    }
    
    s.Conn = conn
    
    return nil
}

func (s *Server) GetGroupsOfUser(username string) ([]string, error) {
    var groups []string
    
    for _, base_dn := range s.SearchBaseDns {
        searchRequest := ldap.NewSearchRequest(
            base_dn,
            ldap.ScopeWholeSubtree, 
            ldap.NeverDerefAliases, 
            0, 0, false,
            fmt.Sprintf(s.SearchFilter, username), 
            []string{"memberOf"},
            nil,
        )
        
        sr, err := s.Conn.Search(searchRequest)
        if err != nil {
            return groups, err
        }
        
        log.Printf("[debug] len %v", len(sr.Entries))
        
        for _, entry := range sr.Entries {
            groups = append(groups, entry.GetAttributeValue("memberOf"))
        }
    }
    
    return groups, nil
}

func (s *Server) Close() {
    s.Conn.Close()
}

func (cfg *Config) UpdatePermissions(user, password string) {
    for _, lc := range cfg.Servers {
    
        if lc.User == "" && lc.Password == "" {
            lc.User = user
            lc.Password = password
        }
        
        log.Printf("[debug] user authenticating %v", lc.User)
    
        if err := lc.LdapNew(); err != nil {
            log.Printf("[error] connect ldap: %v", err)
            continue
        }
        
        //getting ldap groups
        groups, err := lc.GetGroupsOfUser(user)
        if err != nil {
            log.Printf("[error] get ldap user groups: %v", err)
            continue
        }
        
        lc.Close()
        
        for _, attr := range groups {
            log.Printf("[debug] %v", attr)
        }
        
    }
}

func (cfg *Config) ApiLogin(w http.ResponseWriter, r *http.Request) {
    login := Login{}

    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Printf("[error] %v - %s", err, r.URL.Path)
        w.WriteHeader(400)
        w.Write([]byte(err.Error()))
        return
    }

    if err := json.Unmarshal(body, &login); err != nil {
        log.Printf("[error] %v - %s", err, r.URL.Path)
        w.WriteHeader(400)
        w.Write([]byte(err.Error()))
        return
    }

    go cfg.UpdatePermissions(login.User, login.Password)

    w.WriteHeader(204)

}

func main() {
    //command-line flag parsing
    lsAddress      := flag.String("web.listen-address", "0.0.0.0:8082", "listen address")
    cfFile         := flag.String("config.file", "config/ldap.toml", "config file")
    //encrypt_pass   := flag.String("encrypt", "", "encrypt string")
    //decrypt_pass   := flag.Bool("decrypt", false, "decrypt passwords")
    flag.Parse()

    //program completion signal processing
    c := make(chan os.Signal, 2)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <- c
        log.Print("[info] gcontrol stopped")
        os.Exit(0)
    }()
    
    // Loading configuration file
    f, err := os.Open(*cfFile)
    if err != nil {
        log.Fatalf("[error] %v", err)
    }
    var cfg Config
    if err := toml.NewDecoder(f).Decode(&cfg); err != nil {
        log.Fatalf("[error] %v", err)
    }
    f.Close()

	http.HandleFunc("/login", cfg.ApiLogin)
    
    go func(cfg Grafana){
        if cfg.CertFile != "" && cfg.CertKey != "" {
            log.Printf("[info] listen ssl %s", *lsAddress)
            if err := http.ListenAndServeTLS(*lsAddress, cfg.CertFile, cfg.CertKey, nil); err != nil {
                log.Fatalf("[error] %v", err)
            }
        } else {
            log.Printf("[info] listen %s", *lsAddress)
            if err := http.ListenAndServe(*lsAddress, nil); err != nil {
                log.Fatalf("[error] %v", err)
            }
        }
    }(cfg.Grafana)

    log.Print("[info] gcontrol started")
    
    // Daemon mode
    for {
        time.Sleep(60 * time.Second)
    }
}