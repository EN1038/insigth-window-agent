package main
import (
  "fmt"
  "os"
  "github.com/sosecure/insite-agent/internal/app"
  "github.com/sosecure/insite-agent/internal/config"
  "github.com/sosecure/insite-agent/internal/settings"
)
func main() {
  f, _ := os.Create(`C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_hostcheck-out.txt`)
  defer f.Close()
  log := func(s string) { fmt.Fprintln(f, s); fmt.Println(s) }
  base := config.DataBaseDir()
  log("base="+base)
  st := settings.New(base)
  if err := st.Load(); err != nil {
    log("settings_load_err="+err.Error())
  } else {
    log(fmt.Sprintf("settings_ok approved=%v ti=%v", st.GetBool("approved"), st.GetBool(settings.KeyTIBootstrapDone)))
  }
  h, err := app.NewHost(base)
  if err != nil {
    log("host_err="+err.Error())
    os.Exit(1)
  }
  log("host_ok")
  _ = h
}
