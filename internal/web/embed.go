package web

import "embed"

//go:embed templates/*.html static/*
var embeddedFiles embed.FS
