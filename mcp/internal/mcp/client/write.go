/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
)

// Post performs a POST with a JSON body against basePath+path. As with Get,
// path is caller-controlled only — never derived from tool arguments without
// validation.
func (c *Client) Post(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

// Put performs a PUT with an optional JSON body against basePath+path.
func (c *Client) Put(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPut, path, in, out)
}

// Patch performs a PATCH with a JSON body against basePath+path (raw
// middleware endpoints such as PATCH /config/ai/apikey/{key_id}).
func (c *Client) Patch(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPatch, path, in, out)
}

// Delete performs a DELETE against basePath+path.
func (c *Client) Delete(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

// DeleteQ is Delete with URL-encoded query parameters.
func (c *Client) DeleteQ(ctx context.Context, path string, q url.Values, out any) error {
	if len(q) > 0 {
		path = path + "?" + q.Encode()
	}
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

// GetText fetches basePath+path and returns the body as text (for non-JSON
// endpoints such as log archives). The body is capped at maxBytes (<=0 uses
// the client-wide cap).
func (c *Client) GetText(ctx context.Context, path string, maxBytes int64) (string, error) {
	if maxBytes <= 0 || maxBytes > maxBodyBytes {
		maxBytes = maxBodyBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+basePath+path, nil)
	if err != nil {
		return "", err
	}
	if t := c.getToken(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("target %s: GET %s: %w", c.name, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", fmt.Errorf("target %s: GET %s: read: %w", c.name, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("target %s: GET %s: %s", c.name, path,
			statusSnippet(resp.StatusCode, raw))
	}
	return string(raw), nil
}

// PostMultipartFile POSTs content as a multipart file field (the shape
// POST /config/import expects: formData file "configuration").
func (c *Client) PostMultipartFile(ctx context.Context, path, field, filename string, content []byte, out any) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(content); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+basePath+path,
		bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	if t := c.getToken(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("target %s: POST %s: %w", c.name, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("target %s: POST %s: read body: %w", c.name, path, err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("target %s: POST %s: %s", c.name, path,
			statusSnippet(resp.StatusCode, raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("target %s: POST %s: decode: %w", c.name, path, err)
		}
	}
	return nil
}
