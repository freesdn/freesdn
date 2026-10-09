// SPDX-License-Identifier: AGPL-3.0-only
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test-utils";
import { SLAReportsPanel } from "./SLAReportsPanel";

const mock = vi.hoisted(() => ({
  canWrite: true,
  api: {
    list: vi.fn(),
    generate: vi.fn(),
    download: vi.fn(),
    schedules: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    deliveries: vi.fn(),
    cancel: vi.fn(),
  },
  providers: vi.fn(),
}));
vi.mock("@/lib/api/slaReports", () => ({ slaReportsApi: mock.api }));
vi.mock("@/lib/api", () => ({
  notificationApi: { getProviders: mock.providers },
}));
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: unknown) => unknown) =>
    selector({
      user: { id: "reader", organization_id: "org" },
      hasPermission: () => mock.canWrite,
    }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  mock.canWrite = true;
  mock.api.list.mockResolvedValue({ data: { reports: [], total: 0 } });
  mock.api.schedules.mockResolvedValue({ data: { schedules: [], total: 0 } });
  mock.api.deliveries.mockResolvedValue({ data: [] });
  mock.api.create.mockResolvedValue({ data: { id: "schedule" } });
  mock.api.cancel.mockResolvedValue({ data: {} });
  mock.providers.mockResolvedValue({ data: [] });
});

describe("SLA report operator controls", () => {
  it("never silently opts new schedules into email", async () => {
    renderWithProviders(<SLAReportsPanel policies={[]} />);
    expect(
      screen.getByLabelText("Send email notices for future scheduled reports"),
    ).not.toBeChecked();
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Monthly" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create schedule" }));
    await waitFor(() =>
      expect(mock.api.create).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Monthly",
          delivery_enabled: false,
          delivery_provider_id: null,
          recipients: [],
        }),
      ),
    );
  });

  it("retains comma-separated policy IDs while the operator types", async () => {
    renderWithProviders(<SLAReportsPanel policies={[]} />);
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Selected policies" },
    });
    const policies = screen.getByLabelText(/Policy IDs/);
    fireEvent.change(policies, { target: { value: "first, " } });
    expect(policies).toHaveValue("first, ");
    fireEvent.change(policies, { target: { value: "first, second" } });
    fireEvent.click(screen.getByRole("button", { name: "Create schedule" }));
    await waitFor(() =>
      expect(mock.api.create).toHaveBeenCalledWith(
        expect.objectContaining({ sla_policy_ids: ["first", "second"] }),
      ),
    );
  });

  it("explains unknown acceptance and offers no unsafe resend", async () => {
    mock.api.deliveries.mockResolvedValue({
      data: [
        {
          id: "delivery",
          recipient_email: "reader@example.test",
          state: "unknown",
          attempts: 1,
          error_code: "worker_interrupted",
        },
      ],
    });
    renderWithProviders(<SLAReportsPanel policies={[]} />, {
      initialPath: "/sla/reports?report=report-id",
    });
    expect(await screen.findByText("unknown")).toBeInTheDocument();
    expect(
      screen.getByText(/does not prove inbox delivery/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /resend|cancel pending/i }),
    ).not.toBeInTheDocument();
    expect(mock.api.deliveries).toHaveBeenCalledWith("report-id");
  });

  it("lets operators cancel only pending delivery", async () => {
    mock.api.deliveries.mockResolvedValue({
      data: [
        {
          id: "delivery",
          recipient_email: "reader@example.test",
          state: "retry",
          attempts: 1,
          next_attempt_at: "2026-09-23T16:00:00Z",
        },
      ],
    });
    renderWithProviders(<SLAReportsPanel policies={[]} />, {
      initialPath: "/sla/reports?report=report-id",
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "Cancel pending delivery" }),
    );
    await waitFor(() =>
      expect(mock.api.cancel).toHaveBeenCalledWith("report-id", "delivery"),
    );
  });

  it("does not fetch provider settings or delivery recipients for read-only users", async () => {
    mock.canWrite = false;
    renderWithProviders(<SLAReportsPanel policies={[]} />, {
      initialPath: "/sla/reports?report=report-id",
    });
    expect(
      await screen.findByText("No reports have been generated."),
    ).toBeInTheDocument();
    expect(mock.providers).not.toHaveBeenCalled();
    expect(mock.api.deliveries).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Create schedule" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Download linked report" }),
    ).toBeInTheDocument();
  });

  it("reports fetch failures instead of claiming the archive is empty", async () => {
    mock.api.list.mockRejectedValue(new Error("Report service unavailable"));
    renderWithProviders(<SLAReportsPanel policies={[]} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Report service unavailable",
    );
    expect(
      screen.queryByText("No reports have been generated."),
    ).not.toBeInTheDocument();
  });
});
