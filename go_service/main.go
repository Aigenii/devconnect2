package main

import (
    "context"
    "encoding/json"
    "log"
    "math"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "time"
)

type computeResp struct {
    Input  int     `json:"input"`
    Result float64 `json:"result"`
    TookMS int64   `json:"took_ms"`
}

// A simple CPU-bound example: approximate integral of sin(x) from 0..n
func compute(n int) float64 {
    // use a Riemann sum with many steps to make the work non-trivial
    steps := 200000
    h := float64(n) / float64(steps)
    s := 0.0
    for i := 0; i < steps; i++ {
        x := (float64(i)+0.5)*h
        s += math.Sin(x)
    }
    return s * h
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"ok"}`))
}

func computeHandler(w http.ResponseWriter, r *http.Request) {
    // accept ?n=10 (default 10)
    n := 10
    if qs := r.URL.Query().Get("n"); qs != "" {
        if v, err := strconv.Atoi(qs); err == nil && v > 0 {
            n = v
        }
    }

    start := time.Now()
    res := compute(n)
    took := time.Since(start).Milliseconds()

    w.Header().Set("Content-Type", "application/json")
    out := computeResp{Input: n, Result: res, TookMS: took}
    _ = json.NewEncoder(w).Encode(out)
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/health", healthHandler)
    mux.HandleFunc("/compute", computeHandler)

    srv := &http.Server{
        Addr:    ":8081",
        Handler: mux,
        // reasonable timeouts
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // graceful shutdown
    idleConnsClosed := make(chan struct{})
    go func() {
        c := make(chan os.Signal, 1)
        signal.Notify(c, os.Interrupt)
        <-c
        // we received an interrupt signal, shut down.
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := srv.Shutdown(ctx); err != nil {
            log.Printf("HTTP server Shutdown: %v", err)
        }
        close(idleConnsClosed)
    }()

    log.Printf("Go service listening on %s", srv.Addr)
    if err := srv.ListenAndServe(); err != http.ErrServerClosed {
        log.Fatalf("ListenAndServe(): %v", err)
    }

    <-idleConnsClosed
    log.Println("Server stopped")
}
