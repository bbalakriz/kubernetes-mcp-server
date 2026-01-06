package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	internalk8s "github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/klog/v2"
)

func authHeaderPropagationMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if req.GetExtra() != nil && req.GetExtra().Header != nil {
			// Get the standard Authorization header (OAuth compliant)
			authHeader := req.GetExtra().Header.Get(string(internalk8s.OAuthAuthorizationHeader))
			if authHeader != "" {
				return next(context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, authHeader), method, req)
			}

			// Fallback to custom header for backward compatibility
			customAuthHeader := req.GetExtra().Header.Get(string(internalk8s.CustomAuthorizationHeader))
			if customAuthHeader != "" {
				return next(context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, customAuthHeader), method, req)
			}
		}
		return next(ctx, method, req)
	}
}

func toolCallLoggingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch params := req.GetParams().(type) {
		case *mcp.CallToolParamsRaw:
			toolCallRequest, _ := GoSdkToolCallParamsToToolCallRequest(params)
			klog.V(5).Infof("mcp tool call: %s(%v)", toolCallRequest.Name, toolCallRequest.GetArguments())
			if req.GetExtra() != nil && req.GetExtra().Header != nil {
				buffer := bytes.NewBuffer(make([]byte, 0))
				if err := req.GetExtra().Header.WriteSubset(buffer, map[string]bool{"Authorization": true, "authorization": true}); err == nil {
					klog.V(7).Infof("mcp tool call headers: %s", buffer)
				}
			}
		}
		
		// Call the handler
		result, err := next(ctx, method, req)
		
		// Log the response
		if callToolResult, ok := result.(*mcp.CallToolResult); ok {
			klog.V(5).Infof("mcp tool response: isError=%v, contentLength=%d", callToolResult.IsError, len(callToolResult.Content))
			for i, content := range callToolResult.Content {
				if textContent, ok := content.(*mcp.TextContent); ok {
					klog.V(6).Infof("mcp tool response[%d]: %s", i, textContent.Text)
				}
			}
			
			// Log the entire result as JSON to see what actually gets sent over the wire
			// This is critical for debugging JSON parsing errors in clients
			if klog.V(6).Enabled() {
				// Marshal without indentation (same as what goes over the wire)
				if resultJSON, err := json.Marshal(callToolResult); err == nil {
					klog.V(6).Infof("CallToolResult as JSON (length=%d): %s", len(resultJSON), string(resultJSON))
					
					// Log character map for first 200 chars to help debug parsing errors
					if len(resultJSON) > 0 {
						endPos := 200
						if len(resultJSON) < 200 {
							endPos = len(resultJSON)
						}
						klog.V(7).Infof("First %d characters with positions:", endPos)
						klog.V(7).Infof("0         10        20        30        40        50        60        70        80        90        100")
						klog.V(7).Infof("|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|")
						klog.V(7).Infof("%s", string(resultJSON[0:endPos]))
						
						// Show byte values for debugging encoding issues
						var byteStr string
						for i := 0; i < endPos && i < len(resultJSON); i++ {
							if i > 0 && i%10 == 0 {
								byteStr += " "
							}
							byteStr += fmt.Sprintf("%02x", resultJSON[i])
						}
						klog.V(7).Infof("Hex bytes: %s", byteStr)
					}
				} else {
					klog.Errorf("Failed to marshal CallToolResult to JSON: %v", err)
				}
			}
		}
		
		return result, err
	}
}

func toolScopedAuthorizationMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		scopes, ok := ctx.Value(TokenScopesContextKey).([]string)
		if !ok {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but no scope is available", method, method)), nil
		}
		if !slices.Contains(scopes, "mcp:"+method) && !slices.Contains(scopes, method) {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but only scopes %s are available", method, method, scopes)), nil
		}
		return next(ctx, method, req)
	}
}
