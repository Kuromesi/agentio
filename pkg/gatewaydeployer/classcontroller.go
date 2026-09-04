// Copyright 2026 The Kruise Authors
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

package gatewaydeployer

import (
	"errors"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// ClassController creates the built-in GatewayClasses when absent and restores them after deletion.
type ClassController struct {
	queue   controllers.Queue
	classes kclient.Client[*gatewayv1.GatewayClass]
}

func NewClassController(classes kclient.Client[*gatewayv1.GatewayClass]) *ClassController {
	gc := &ClassController{classes: classes}
	gc.queue = controllers.NewQueue("gateway class",
		controllers.WithReconciler(gc.Reconcile),
		controllers.WithMaxAttempts(25))
	gc.classes.AddEventHandler(controllers.FilteredObjectHandler(gc.queue.AddObject, func(o controllers.Object) bool {
		_, f := builtinClasses[o.GetName()]
		return f
	}))
	return gc
}

// Run runs the reconcile queue until stop closes, then shuts down its event handlers.
func (c *ClassController) Run(stop <-chan struct{}) {
	defer c.classes.ShutdownHandlers()
	c.queue.Add(types.NamespacedName{})
	c.queue.Run(stop)
}

func (c *ClassController) Reconcile(types.NamespacedName) error {
	var errs []error
	for class := range builtinClasses {
		if err := c.reconcileClass(class); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *ClassController) reconcileClass(class string) error {
	current := c.classes.Get(class, "")
	if current != nil {
		info := builtinClasses[class]
		if current.Spec.ControllerName != gatewayv1.GatewayController(info.controller) {
			return nil
		}
		existing := apiMeta.FindStatusCondition(current.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
		if conditionMatches(existing, metav1.ConditionTrue, current.Generation,
			string(gatewayv1.GatewayClassReasonAccepted), "Handled by Agentio controller") {
			return nil
		}
		updated := current.DeepCopy()
		apiMeta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: current.Generation,
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            "Handled by Agentio controller",
		})
		_, err := c.classes.UpdateStatus(updated)
		return err
	}
	info := builtinClasses[class]
	description := info.description
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: class},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(info.controller),
			Description:    &description,
		},
	}
	// Tolerate IsConflict and IsAlreadyExists: the cold informer cache can race a Create the API server already accepted.
	if _, err := c.classes.Create(gc); err != nil && !kerrors.IsConflict(err) && !kerrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func conditionMatches(existing *metav1.Condition, status metav1.ConditionStatus, generation int64, reason, message string) bool {
	if existing == nil {
		return false
	}
	return existing.Status == status && existing.ObservedGeneration == generation &&
		existing.Reason == reason && existing.Message == message
}
