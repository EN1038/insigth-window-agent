package main
import (
  "fmt"
  "github.com/sosecure/insite-agent/internal/config"
  "github.com/sosecure/insite-agent/internal/settings"
  "github.com/sosecure/insite-agent/internal/ssdeepscan"
)
func main() {
  base := config.DataBaseDir()
  st := settings.New(base); _ = st.Load()
  store := ssdeepscan.NewStore(base)
  idx,_ := store.LoadIndex()
  fmt.Println("total", idx.Total, "version", st.Get(settings.KeySsdeepDBVersion,""))
  list,_ := store.LoadShard(48)
  for i,s := range list {
    if i>=5 { break }
    fmt.Println(s.Name, "family=", s.Family)
  }
}
