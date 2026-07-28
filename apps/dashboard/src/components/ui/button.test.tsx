import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Button } from "./button";

describe("Button", () => {
  it("renders a button by default", () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });

  it("disables itself and announces work while loading", () => {
    render(<Button loading>Save</Button>);
    const button = screen.getByRole("button");
    expect(button).toBeDisabled();
    expect(screen.getByText("Working…")).toBeInTheDocument();
  });

  it("composes onto a single child without throwing", () => {
    // Radix Slot accepts exactly one element child. Passing it the spinner *and* the
    // child threw "Slot failed to slot onto its children" and crashed every page that
    // used `<Button asChild><Link/></Button>` — this pins the fix.
    expect(() =>
      render(
        <Button asChild>
          <a href="/applications">
            <svg aria-hidden />
            Manage applications
          </a>
        </Button>,
      ),
    ).not.toThrow();

    const link = screen.getByRole("link", { name: /Manage applications/ });
    expect(link).toHaveAttribute("href", "/applications");
    // Variant classes must still reach the composed element.
    expect(link.className).toContain("bg-primary");
  });

  it("does not inject a spinner into a composed child", () => {
    render(
      <Button asChild loading>
        <a href="/x">Go</a>
      </Button>,
    );
    expect(screen.queryByText("Working…")).not.toBeInTheDocument();
  });
});
