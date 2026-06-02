package nuclei

import (
	tpl "github.com/kN6jq/nuclei-sdk/template"
	"github.com/kN6jq/nuclei-sdk/interactsh"
	"github.com/kN6jq/nuclei-sdk/matcher"
	"github.com/kN6jq/nuclei-sdk/extractor"
	"github.com/kN6jq/nuclei-sdk/variables"
	"github.com/kN6jq/nuclei-sdk/dsl"
)

// Types re-exported from template package
type Template = tpl.Template
type Result = tpl.Result
type Info = tpl.Info
type Classification = tpl.Classification
type ResponseData = tpl.ResponseData
type Request = tpl.Request
type ExecuteOptions = tpl.ExecuteOptions

// Types re-exported from matcher package
type Matcher = matcher.Matcher

// Types re-exported from extractor package
type Extractor = extractor.Extractor

// Types re-exported from interactsh package
type InteractshClient = interactsh.Client
type InteractshOptions = interactsh.Options
type InteractshTrackedEntry = interactsh.TrackedEntry
type InteractshOOBResult = interactsh.OOBResult

// MatcherType constants
const (
	MatcherWord   = matcher.MatcherWord
	MatcherRegex  = matcher.MatcherRegex
	MatcherStatus = matcher.MatcherStatus
	MatcherDSL    = matcher.MatcherDSL
)

// Template methods are inherited via type alias

// Package-level functions re-exported from template package
var LoadFromDir = tpl.LoadFromDir
var LoadFromFS = tpl.LoadFromFS
var Parse = tpl.Parse

// DSL functions
var EvaluateDSL = dsl.EvaluateDSL
var EvaluateDSLBool = dsl.EvaluateDSLBool

// Variables functions
var BuildVariableContext = variables.BuildVariableContext
var Substitute = variables.Substitute

// Interactsh functions
var NewInteractshClient = interactsh.New
var InteractshDefaultOptions = interactsh.DefaultOptions
var InteractshHasMarkers = interactsh.HasMarkers
var InteractshHasMatchers = interactsh.HasMatchers