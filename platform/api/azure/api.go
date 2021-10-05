// Copyright 2016 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/classic/management"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-03-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2020-11-01/network"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2020-10-01/resources"
	armStorage "github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2021-01-01/storage"
	"github.com/Azure/azure-sdk-for-go/storage"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/coreos/pkg/capnslog"

	internalAuth "github.com/flatcar-linux/mantle/auth"
)

var (
	plog = capnslog.NewPackageLogger("github.com/flatcar-linux/mantle", "platform/api/azure")
)

type API struct {
	client     management.Client
	rgClient   resources.GroupsClient
	imgClient  compute.ImagesClient
	compClient compute.VirtualMachinesClient
	netClient  network.VirtualNetworksClient
	subClient  network.SubnetsClient
	ipClient   network.PublicIPAddressesClient
	intClient  network.InterfacesClient
	accClient  armStorage.AccountsClient
	opts       *Options
}

// New creates a new Azure client. If no publish settings file is provided or
// can't be parsed, an anonymous client is created.
func New(opts *Options) (*API, error) {
	conf := management.DefaultConfig()
	conf.APIVersion = "2015-04-01"

	if opts.ManagementURL != "" {
		conf.ManagementURL = opts.ManagementURL
	}

	if opts.StorageEndpointSuffix == "" {
		opts.StorageEndpointSuffix = storage.DefaultBaseURL
	}

	profiles, err := internalAuth.ReadAzureProfile(opts.AzureProfile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read Azure profile: %v", err)
	}

	subOpts := profiles.SubscriptionOptions(opts.AzureSubscription)
	if subOpts == nil {
		return nil, fmt.Errorf("Azure subscription named %q doesn't exist in %q", opts.AzureSubscription, opts.AzureProfile)
	}

	if os.Getenv("AZURE_AUTH_LOCATION") == "" {
		if opts.AzureAuthLocation == "" {
			user, err := user.Current()
			if err != nil {
				return nil, err
			}
			opts.AzureAuthLocation = filepath.Join(user.HomeDir, internalAuth.AzureAuthPath)
		}
		// TODO: Move to Flight once built to allow proper unsetting
		os.Setenv("AZURE_AUTH_LOCATION", opts.AzureAuthLocation)
	}

	if opts.SubscriptionID == "" {
		opts.SubscriptionID = subOpts.SubscriptionID
	}

	if opts.SubscriptionName == "" {
		opts.SubscriptionName = subOpts.SubscriptionName
	}

	if opts.ManagementURL == "" {
		opts.ManagementURL = subOpts.ManagementURL
	}

	if opts.ManagementCertificate == nil {
		opts.ManagementCertificate = subOpts.ManagementCertificate
	}

	if opts.StorageEndpointSuffix == "" {
		opts.StorageEndpointSuffix = subOpts.StorageEndpointSuffix
	}

	var client management.Client
	if opts.ManagementCertificate != nil {
		client, err = management.NewClientFromConfig(opts.SubscriptionID, opts.ManagementCertificate, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create azure client: %v", err)
		}
	} else {
		client = management.NewAnonymousClient()
	}

	api := &API{
		client: client,
		opts:   opts,
	}

	err = api.resolveImage()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image: %v", err)
	}

	return api, nil
}

func (a *API) SetupClients() error {
	auther, err := auth.NewAuthorizerFromFile(resources.DefaultBaseURI)
	if err != nil {
		return err
	}
	settings, err := auth.GetSettingsFromFile()
	if err != nil {
		return err
	}
	a.rgClient = resources.NewGroupsClient(settings.GetSubscriptionID())
	a.rgClient.Authorizer = auther

	auther, err = auth.NewAuthorizerFromFile(compute.DefaultBaseURI)
	if err != nil {
		return err
	}
	a.imgClient = compute.NewImagesClient(settings.GetSubscriptionID())
	a.imgClient.Authorizer = auther
	a.compClient = compute.NewVirtualMachinesClient(settings.GetSubscriptionID())
	a.compClient.Authorizer = auther

	auther, err = auth.NewAuthorizerFromFile(network.DefaultBaseURI)
	if err != nil {
		return err
	}
	a.netClient = network.NewVirtualNetworksClient(settings.GetSubscriptionID())
	a.netClient.Authorizer = auther
	a.subClient = network.NewSubnetsClient(settings.GetSubscriptionID())
	a.subClient.Authorizer = auther
	a.ipClient = network.NewPublicIPAddressesClient(settings.GetSubscriptionID())
	a.ipClient.Authorizer = auther
	a.intClient = network.NewInterfacesClient(settings.GetSubscriptionID())
	a.intClient.Authorizer = auther

	auther, err = auth.NewAuthorizerFromFile(armStorage.DefaultBaseURI)
	if err != nil {
		return err
	}
	a.accClient = armStorage.NewAccountsClient(settings.GetSubscriptionID())
	a.accClient.Authorizer = auther

	return nil
}

func randomName(prefix string) string {
	b := make([]byte, 5)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

func (a *API) GetOpts() *Options {
	return a.opts
}

func (a *API) GC(gracePeriod time.Duration) error {
	durationAgo := time.Now().Add(-1 * gracePeriod)

	listGroups, err := a.ListResourceGroups("")
	if err != nil {
		return fmt.Errorf("listing resource groups: %v", err)
	}

	for _, l := range *listGroups.Value {
		if strings.HasPrefix(*l.Name, "kola-cluster") {
			createdAt := *l.Tags["createdAt"]
			timeCreated, err := time.Parse(time.RFC3339, createdAt)
			if err != nil {
				return fmt.Errorf("error parsing time: %v", err)
			}
			if !timeCreated.After(durationAgo) {
				if err = a.TerminateResourceGroup(*l.Name); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
