package aws

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// deletes VPCs that are not associated with any active osde2e cluster
func (CcsAwsSession *ccsAwsSession) CleanupVPCs(activeClusters map[string]bool, dryrun bool, sendSummary bool,
	deletedCounter *int, failedCounter *int, errorBuilder *strings.Builder,
) error {
	err := CcsAwsSession.GetAWSSessions()
	if err != nil {
		return err
	}

	// Get osde2e VPCs from AWS
	results, err := CcsAwsSession.ec2.DescribeVpcs(&ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{aws.String("osde2e-*")},
			},
		},
	})
	if err != nil {
		return err
	}

	if len(results.Vpcs) == 0 {
		log.Printf("No VPCs found\n")
		return nil
	}

	log.Printf("VPCs found: %d\n", len(results.Vpcs))

	var vpcStacks []string
	for _, vpc := range results.Vpcs {
		var vpcName string
		nameTagFound := false
		for _, tag := range vpc.Tags {
			if tag.Key != nil && tag.Value != nil && *tag.Key == "Name" {
				vpcName = *tag.Value
				nameTagFound = true
				break
			}
		}

		// Skip if no Name tag found
		if !nameTagFound {
			log.Printf("Skipping VPC %s with no Name tag\n", *vpc.VpcId)
			continue
		}

		vpcStacks = append(vpcStacks, getClusterNameFromVPCName(vpcName))
	}

	// Create a map with VPC stack names (cluster-name + "-vpc") from active osde2e clusters
	activeVpcStacks := make(map[string]bool)
	for clusterName := range activeClusters {
		vpcStackName := clusterName + "-vpc"
		activeVpcStacks[vpcStackName] = true
		log.Printf("Cluster %s expects VPC stack: %s\n", clusterName, vpcStackName)
	}

	// Create CloudFormation client early to check stack existence
	cfnClient := cloudformation.New(CcsAwsSession.session)
	if cfnClient == nil {
		return fmt.Errorf("failed to create CloudFormation client")
	}

	// Only delete VPC stacks that are not associated with any cluster and actually exist
	var orphanedStacks []string
	for _, vpcStackName := range vpcStacks {
		if !activeVpcStacks[vpcStackName] {
			// Check if the CloudFormation stack actually exists before adding to orphaned list
			_, err := cfnClient.DescribeStacks(&cloudformation.DescribeStacksInput{
				StackName: aws.String(vpcStackName),
			})
			if err != nil {
				// Stack doesn't exist, skip it
				log.Printf("VPC stack %s does not exist in CloudFormation, skipping\n", vpcStackName)
				continue
			}

			log.Printf("Found orphaned VPC stack: %s\n", vpcStackName)
			orphanedStacks = append(orphanedStacks, vpcStackName)
		} else {
			log.Printf("VPC stack %s has corresponding cluster, skipping\n", vpcStackName)
		}
	}

	log.Printf("Found %d orphaned VPC stacks to delete\n", len(orphanedStacks))

	for _, stackName := range orphanedStacks {
		fmt.Printf("Attempting to delete CloudFormation stack: %s\n", stackName)

		if !dryrun {
			// Workaround: Delete leftover security groups before deleting the stack
			if err := CcsAwsSession.cleanupVPCSecurityGroups(cfnClient, stackName); err != nil {
				log.Printf("Warning: failed to cleanup security groups for %s: %v\n", stackName, err)
				// Continue with stack deletion even if SG cleanup fails
			}

			_, err := cfnClient.DeleteStack(&cloudformation.DeleteStackInput{
				StackName: aws.String(stackName),
			})
			if err != nil {
				*failedCounter++
				errorMsg := fmt.Sprintf("Failed to delete CloudFormation stack %s: %v\n", stackName, err)
				fmt.Print(errorMsg)
				if sendSummary && errorBuilder.Len() < 10000 {
					errorBuilder.WriteString(errorMsg)
				}
				continue
			}

			err = cfnClient.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{
				StackName: aws.String(stackName),
			})
			if err != nil {
				*failedCounter++
				errorMsg := fmt.Sprintf("Failed waiting for stack deletion %s: %v\n", stackName, err)
				fmt.Print(errorMsg)
				if sendSummary && errorBuilder.Len() < 10000 {
					errorBuilder.WriteString(errorMsg)
				}
				continue
			}

			*deletedCounter++
			log.Printf("AWS VPC stack %s successfully deleted\n", stackName)
		} else {
			log.Printf("Would delete AWS VPC stack %s\n", stackName)
		}
	}

	return nil
}

// removes the -yyyyy suffix from VPC names that follow the osde2e-xxxxx-yyyyy-vpc format
func getClusterNameFromVPCName(vpcName string) string {
	// Match osde2e-xxxxx-yyyyy-vpc pattern and extract osde2e-xxxxx-vpc part
	re := regexp.MustCompile(`^(osde2e-[^-]+)-[^-]+-vpc$`)
	matches := re.FindStringSubmatch(vpcName)
	if len(matches) == 2 {
		return matches[1] + "-vpc"
	}
	// If pattern doesn't match, return original name
	return vpcName
}

// cleanupVPCSecurityGroups deletes leftover security groups in the VPC before stack deletion
// Workaround for https://issues.redhat.com/browse/OCPBUGS-74960
// TODO: Remove the workaround once the bug is fixed
func (CcsAwsSession *ccsAwsSession) cleanupVPCSecurityGroups(cfnClient *cloudformation.CloudFormation, stackName string) error {
	// Get VPC ID from stack outputs
	stackOutput, err := cfnClient.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		return fmt.Errorf("failed to describe stack: %v", err)
	}

	if len(stackOutput.Stacks) == 0 {
		return fmt.Errorf("stack not found")
	}

	var vpcID string
	for _, output := range stackOutput.Stacks[0].Outputs {
		if output.OutputKey != nil && *output.OutputKey == "VPCId" {
			if output.OutputValue != nil {
				vpcID = *output.OutputValue
				break
			}
		}
	}

	if vpcID == "" {
		return fmt.Errorf("VPC ID not found in stack outputs")
	}

	log.Printf("Cleaning up security groups in VPC: %s\n", vpcID)

	// List all security groups in the VPC with vpce-private-router in the name
	result, err := CcsAwsSession.ec2.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(vpcID)},
			},
			{
				Name:   aws.String("group-name"),
				Values: []*string{aws.String("*vpce-private-router*")},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %v", err)
	}

	// Delete security groups matching vpce-private-router
	for _, sg := range result.SecurityGroups {
		if sg.GroupId == nil {
			continue
		}

		log.Printf("Deleting vpce-private-router security group: %s (name: %s)\n", *sg.GroupId, aws.StringValue(sg.GroupName))

		// Delete the security group
		_, err := CcsAwsSession.ec2.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
			GroupId: sg.GroupId,
		})
		if err != nil {
			log.Printf("Failed to delete security group %s: %v\n", *sg.GroupId, err)
			// Continue to try deleting other security groups
		}
	}

	return nil
}
