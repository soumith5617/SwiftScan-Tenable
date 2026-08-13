import DOMPurify from "dompurify";

const ALLOWED_TAGS = [
  "strong",
  "em",
  "b",
  "i",
  "code",
  "pre",
  "br",
  "p",
  "span",
  "ul",
  "ol",
  "li",
  "table",
  "thead",
  "tbody",
  "tr",
  "th",
  "td",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "blockquote",
  "a",
];

const ALLOWED_ATTR = ["href", "target", "rel", "class", "title"];

/**
 * Sanitizes HTML strings generated from AI models, user inputs, or external scanner data
 * before rendering via dangerouslySetInnerHTML.
 */
export function sanitizeHtml(dirty: string): string {
  if (!dirty) return "";
  if (typeof window === "undefined") {
    return dirty.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
  }
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
  });
}
