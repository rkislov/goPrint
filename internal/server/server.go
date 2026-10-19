// Package server exposes the local administrator API and a small web console.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/rkislov/goPrint/internal/backend"
	"github.com/rkislov/goPrint/internal/queue"
)

type Server struct {
	Store *queue.Store
	Token string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, console)
	})
	api := http.NewServeMux()
	api.HandleFunc("GET /api/printers", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.Printers(r.Context())
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/printers", s.addPrinter)
	api.HandleFunc("PUT /api/printers/{id}/paused", s.pause)
	api.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, r *http.Request) { v, err := s.Store.Jobs(r.Context()); respond(w, v, err) })
	api.HandleFunc("GET /api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.Job(r.Context(), r.PathValue("id"))
		respond(w, v, err)
	})
	api.HandleFunc("POST /api/jobs", s.submit)
	api.HandleFunc("POST /api/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		err := s.Store.Cancel(r.Context(), r.PathValue("id"))
		respond(w, map[string]string{"state": "canceled"}, err)
	})
	api.HandleFunc("GET /api/jobs/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.Events(r.Context(), r.PathValue("id"))
		respond(w, v, err)
	})
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		api.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'")
		// Block browser requests from other origins, including requests through DNS rebinding.
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		message := "internal server error"
		switch {
		case errors.Is(err, queue.ErrNotFound):
			status = 404
			message = err.Error()
		case errors.Is(err, queue.ErrConflict):
			status = 409
			message = err.Error()
		case errors.Is(err, queue.ErrTooLarge):
			status = 413
			message = err.Error()
		}
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "expected one JSON object", 400)
		return false
	}
	return true
}
func (s *Server) addPrinter(w http.ResponseWriter, r *http.Request) {
	var p queue.Printer
	if !decode(w, r, &p) {
		return
	}
	if err := backend.Validate(p); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	v, err := s.Store.AddPrinter(r.Context(), p)
	respond(w, v, err)
}
func (s *Server) pause(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Paused bool `json:"paused"`
	}
	if !decode(w, r, &p) {
		return
	}
	err := s.Store.Pause(r.Context(), r.PathValue("id"), p.Paused)
	respond(w, p, err)
}
func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	format, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "valid Content-Type required", 400)
		return
	}
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Untitled"
	}
	if len(title) > 255 || strings.ContainsAny(title, "\r\n\x00") {
		http.Error(w, "invalid title", 400)
		return
	}
	p, err := s.Store.Printer(r.Context(), r.URL.Query().Get("printer"))
	if err != nil {
		respond(w, nil, err)
		return
	}
	allowed := false
	for _, f := range p.Formats {
		if f == format {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "document format not accepted by printer", 415)
		return
	}
	if r.ContentLength > queue.MaxDocumentSize {
		http.Error(w, "document exceeds size limit", 413)
		return
	}
	// LimitReader in Store also protects chunked requests without Content-Length.
	j, err := s.Store.Submit(r.Context(), p.ID, "local-admin", title, format, r.Body)
	if err != nil {
		if errors.Is(err, queue.ErrTooLarge) {
			respond(w, nil, err)
		} else {
			http.Error(w, "document could not be accepted", 400)
		}
		return
	}
	w.Header().Set("Location", "/api/jobs/"+j.ID)
	w.Header().Set("Content-Length", strconv.Itoa(len(mustJSON(j))))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(mustJSON(j))
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

const console = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>GoPrint</title>
<style>body{font:16px system-ui;max-width:1050px;margin:40px auto;padding:0 20px;color:#202428;background:#f7f8fa}input,select,button{font:inherit;padding:9px;margin:4px 0}button{cursor:pointer}label{display:block;margin-top:10px}section{margin:30px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:15px}small{display:block}#status{min-height:24px}li{margin:12px 0}a{color:inherit}</style>
<h1>GoPrint</h1><p>Локальная консоль администратора · первая версия</p><label>Токен администратора <input id="token" type="password" autocomplete="off"></label><button id="connect">Подключиться / обновить</button><small>Токен хранится только в памяти страницы. Обновление данных — вручную.</small><p id="status" role="status"></p>
<section><h2>Добавить принтер</h2><form id="printer"><label>Имя <input id="name" required maxlength="128"></label><label>URI <input id="uri" placeholder="ipp://printer:631/ipp/print" required size="40"></label><label>Формат документа <select id="format"><option>application/pdf</option><option>application/octet-stream</option><option>application/postscript</option><option>image/pwg-raster</option><option>image/jpeg</option></select></label><button>Добавить</button></form><small>Конвертация отсутствует: принтер должен поддерживать выбранный формат.</small></section>
<section><h2>Принтеры</h2><ul id="printers"></ul></section>
<section><h2>Отправить документ</h2><form id="upload"><label>Принтер <select id="target" required></select></label><label>Файл <input id="file" type="file" required></label><label>Тип содержимого <select id="content"><option>application/pdf</option><option>application/octet-stream</option><option>application/postscript</option><option>image/pwg-raster</option><option>image/jpeg</option></select></label><button>В очередь</button></form></section>
<section><h2>Задания</h2><small>submitted — передано устройству; unknown — результат неизвестен, проверьте принтер перед повторной отправкой. Отмена доступна для queued.</small><ul id="jobs"></ul></section>
<script>
const el=id=>document.getElementById(id);
async function api(path,options={}){const r=await fetch('/api/'+path,{...options,headers:{Authorization:'Bearer '+el('token').value,...options.headers}});if(!r.ok)throw Error(await r.text());return r.json()}
function run(fn){return async e=>{e.preventDefault();try{el('status').textContent='Выполняется…';await fn();el('status').textContent='Готово'}catch(err){el('status').textContent=err.message}}}
async function refresh(){const ps=await api('printers');el('printers').replaceChildren();el('target').replaceChildren();for(const p of ps){const li=document.createElement('li');li.textContent=p.name+' · '+p.uri+' · '+(p.paused?'пауза':'активен')+' ';const b=document.createElement('button');b.textContent=p.paused?'Возобновить':'Пауза';b.onclick=run(async()=>{await api('printers/'+p.id+'/paused',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({paused:!p.paused})});await refresh()});li.append(b);el('printers').append(li);const o=document.createElement('option');o.value=p.id;o.textContent=p.name;el('target').append(o)}const js=await api('jobs');el('jobs').replaceChildren();for(const j of js){const li=document.createElement('li');li.textContent=j.title+' · '+j.state+' · '+j.size+' bytes · '+j.detail+' ';if(j.state==='queued'){const b=document.createElement('button');b.textContent='Отменить';b.onclick=run(async()=>{await api('jobs/'+j.id+'/cancel',{method:'POST'});await refresh()});li.append(b)}el('jobs').append(li)}}
el('connect').onclick=run(refresh);el('printer').onsubmit=run(async()=>{await api('printers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:el('name').value,uri:el('uri').value,formats:[el('format').value]})});await refresh()});el('upload').onsubmit=run(async()=>{const f=el('file').files[0];await api('jobs?printer='+encodeURIComponent(el('target').value)+'&title='+encodeURIComponent(f.name),{method:'POST',headers:{'Content-Type':el('content').value},body:f});await refresh()});
</script></html>`
