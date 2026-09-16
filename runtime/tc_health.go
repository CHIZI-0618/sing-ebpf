//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/sagernet/netlink"
)

// healthCheck is the read-only first stage of the low-frequency watchdog. It
// inspects only resources the runtime already owns; mutation and full topology
// reconciliation remain in reconcile/repairInfrastructure and run only after
// this check reports drift.
func (d *tcDataPlane) healthCheck(
	localInterface string,
	sharedInterfaces []string,
	hostAddresses []netip.Addr,
) (bool, error) {
	if d == nil {
		return true, nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil || d.backend.IsClosed() || d.backend.RequiresRebuild() || d.closing {
		return false, nil
	}
	if len(d.retiredAttachments) != 0 || len(d.retiredDeliveries) != 0 ||
		!slices.Equal(d.hostAddresses, hostAddresses) {
		return false, nil
	}
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return false, nil
	}
	for _, attachment := range d.attachments {
		attached, checkErr := attachment.filtersAttached(d.priority, d.backend)
		if checkErr != nil || !attached {
			return false, checkErr
		}
	}
	routingHealthy, err := d.routing.healthy()
	if err != nil || !routingHealthy {
		return false, err
	}
	if d.delivery != nil {
		deliveryHealthy, checkErr := d.delivery.healthy(d.priority)
		if checkErr != nil || !deliveryHealthy {
			return false, checkErr
		}
	}
	return true, nil
}

func (r *tcPolicyRouting) healthy() (bool, error) {
	if r == nil {
		return false, nil
	}
	for _, family := range r.families {
		expectedRoutes := make([]netlink.Route, 0, len(r.routes))
		for _, route := range r.routes {
			if route.Family == family {
				expectedRoutes = append(expectedRoutes, route)
			}
		}
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: r.table},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return false, err
		}
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				return false, nil
			}
		}
		for _, expected := range expectedRoutes {
			if !slices.ContainsFunc(routes, func(route netlink.Route) bool {
				return matchesTCPolicyRoute(route, []netlink.Route{expected})
			}) {
				return false, nil
			}
		}
		expectedRule := tcPolicyRuleFor(family, r.mark, r.table, r.priority)
		entries, err := listTCPolicyRules(family, *expectedRule)
		if err != nil {
			return false, err
		}
		rulePresent := false
		for _, rule := range entries {
			if rule.owned {
				rulePresent = true
				continue
			}
			if rule.table == r.table {
				return false, nil
			}
		}
		if !rulePresent {
			return false, nil
		}
	}
	return true, nil
}

func (d *tcDeliveryLink) healthy(priority uint16) (bool, error) {
	if d == nil || d.redirect == nil || d.delivery == nil || d.filter == nil {
		return false, nil
	}
	redirect, err := netlink.LinkByName(d.redirectName)
	if err != nil {
		if tcLinkNotFound(err) {
			return false, nil
		}
		return false, err
	}
	delivery, err := netlink.LinkByName(d.deliveryName)
	if err != nil {
		if tcLinkNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if redirect.Attrs().Index != d.redirect.Attrs().Index ||
		delivery.Attrs().Index != d.delivery.Attrs().Index ||
		redirect.Attrs().Flags&net.FlagUp == 0 || delivery.Attrs().Flags&net.FlagUp == 0 {
		return false, nil
	}
	attached, err := tcFilterAttached(
		delivery,
		netlink.HANDLE_MIN_INGRESS,
		"sb_tc_deliver",
		tcDeliveryFilterHandle,
		priority,
	)
	if err != nil || !attached {
		return false, err
	}
	for _, setting := range []struct {
		name string
		want string
	}{
		{name: "rp_filter", want: "0"},
		{name: "accept_local", want: "1"},
	} {
		value, readErr := os.ReadFile(tcInterfaceSysctlPath(d.deliveryName, setting.name))
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				return false, nil
			}
			return false, readErr
		}
		if strings.TrimSpace(string(value)) != setting.want {
			return false, nil
		}
	}
	aggregate, err := os.ReadFile(tcInterfaceSysctlPath("all", "rp_filter"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err == nil && strings.TrimSpace(string(aggregate)) != "0" {
		return false, nil
	}
	return true, nil
}
